// RouterLab: Orchestration Layer to Automate Experiments on Network Routers
// Copyright (C) 2022-2025 Tibor Schneider <sctibor@ethz.ch> and Roland Schmid <roschmi@ethz.ch>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! This module is responsible to manage routers (VDCs). It contains methods to generate the
//! configuration. In addition, it contains a client handle over SSH that can push new
//! configuratoin, change configuration and get the current forwarding or routing state of the
//! device.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashMap, HashSet},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use bgpsim::{
    config::ConfigModifier,
    export::{
        cisco_frr_generators::{
            Interface, RouteMapItem, RouterBgp, RouterBgpNeighbor, Target::CiscoNexus7000,
        },
        Addressor, CiscoFrrCfgGen, DefaultAddressor, ExportError, ExternalCfgGen, InternalCfgGen,
    },
    prelude::*,
};
use ipnet::Ipv4Net;
use itertools::Itertools;
use serde::Deserialize;
use tokio::{
    process::Command,
    sync::{broadcast, mpsc},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    config::{RouterProperties, CONFIG, ROUTERS, VDCS},
    server::ExternalRouterHandle,
    ssh::SshSession,
    Active, RouterLab, RouterLabError, Inactive,
};

mod session;
pub use session::{
    invert_config, BgpNeighbor, BgpPathType, BgpRoute, BgpRoutesDetailError, CiscoSession,
    CiscoShell, CiscoShellError, OspfNeighbor, OspfRoute, ParseError, TableParseError,
};

const OSPF_CONVERGENCE_THRESHOLD_SECS: u64 = 10;
const BGP_CONVERGENCE_THRESHOLD_SECS: u64 = 10;
const BGP_PEC_CHECK: usize = 10;

impl<'n, P: Prefix, Q, Ospf: OspfImpl> RouterLab<'n, P, Q, Ospf, Inactive> {
    /// Prepare all internal routers (used in the constructor of `RouterLab`).
    pub(super) fn prepare_internal_routers<S: AsRef<str>>(
        net: &'n Network<P, Q, Ospf>,
        internal_binding: &HashMap<RouterId, S>,
        external_binding: &HashMap<RouterId, S>,
    ) -> Result<BTreeMap<RouterId, (&'static RouterProperties, CiscoFrrCfgGen<P>)>, RouterLabError>
    {
        // prepare the list of VDCs to choose from (remove bound external routers and we will later
        // remove the internal routers that we bind to)
        let external_vdcs: Vec<_> = external_binding
            .values()
            .map(|vdc_name| vdc_name.as_ref().to_string())
            .collect();
        let mut vdcs: Vec<&'static RouterProperties> = VDCS
            .iter()
            .filter(|vdc| !external_vdcs.contains(&vdc.ssh_name))
            .collect();

        // get all internal routers
        let mut internal_routers = net.internal_indices().collect::<Vec<_>>();
        // sort by their degree
        internal_routers
            .sort_by_key(|r| (Reverse(net.get_topology().neighbors(*r).count()), r.index()));
        let n = internal_routers.len();

        let mut result: BTreeMap<RouterId, (&'static RouterProperties, CiscoFrrCfgGen<P>)> =
            Default::default();

        // assign all routers found in binding
        for (r, vdc_name) in internal_binding {
            let vdc_name = vdc_name.as_ref();
            // remove the router from the set of internal routers that still need to be assigned
            let Some(r_idx) = internal_routers.iter().position(|x| x == r) else {
                return Err(RouterLabError::Network(NetworkError::DeviceNotFound(*r)));
            };
            internal_routers.remove(r_idx);
            let Some(vdc_idx) = vdcs.iter().position(|x| x.ssh_name.as_str() == vdc_name) else {
                return Err(RouterLabError::UnknownVdc(vdc_name.to_string()));
            };
            let vdc = vdcs.remove(vdc_idx);
            result.insert(*r, Self::prepare_router(net, *r, vdc)?);
        }

        // assign routers not explicitly assigned in the bindings
        for (i, r) in internal_routers.into_iter().enumerate() {
            let vdc = vdcs
                .get(i)
                .ok_or_else(|| RouterLabError::TooManyRouters(n))?;
            result.insert(r, Self::prepare_router(net, r, vdc)?);
        }

        Ok(result)
    }

    fn prepare_router(
        net: &'n Network<P, Q, Ospf>,
        r: RouterId,
        vdc: &'static RouterProperties,
    ) -> Result<(&'static RouterProperties, CiscoFrrCfgGen<P>), RouterLabError> {
        let mut gen = CiscoFrrCfgGen::new(
            net,
            r,
            CiscoNexus7000,
            vdc.ifaces.iter().map(|x| x.iface.clone()).collect(),
        )?;
        gen.set_ospf_parameters(None, None);
        for iface in vdc.ifaces.iter() {
            gen.set_mac_address(&iface.iface, iface.mac);
        }
        Ok((vdc, gen))
    }

    /// Connect to all routers in parallel, and return a HashMap with all sessions. If any
    /// connection fails, the function will return an error.
    pub(crate) async fn connect_all_routers(
        &self,
    ) -> Result<HashMap<RouterId, CiscoSession>, RouterLabError> {
        log::debug!("Connect to all routers");

        let mut sessions: HashMap<RouterId, CiscoSession> = HashMap::new();

        for (ssh_name, job) in VDCS
            .iter()
            .map(|r| r.ssh_name.as_str())
            .map(|name| (name, tokio::spawn(CiscoSession::new_with_reset(name))))
            .collect::<Vec<_>>()
        {
            let session = job.await??;

            // store the session for an internal router
            if let Some((r, _)) = self
                .routers
                .iter()
                .find(|(_, (c, _))| c.ssh_name == ssh_name)
            {
                sessions.insert(*r, session);
            // or for an external router
            } else if let Some(ext) = self.external_routers.iter().find_map(|(ext, handle)| {
                if let ExternalRouterHandle::CiscoFrr(vdc, _cisco_frr_gen, _exabgp_info, _routes) =
                    handle
                {
                    if vdc.ssh_name == ssh_name {
                        return Some(ext);
                    }
                }
                None
            }) {
                sessions.insert(*ext, session);
            }
        }

        // check that all internal routers have a session connected
        for (r, (c, _)) in &self.routers {
            if !sessions.contains_key(r) {
                log::error!(
                    "No SSH session created for {} (on {})",
                    r.fmt(self.net),
                    c.ssh_name
                );
                return Err(RouterLabError::Network(NetworkError::DeviceNotFound(*r)));
            }
        }
        // check that all physical external routers have a session connected
        for (ext, c) in self
            .external_routers
            .iter()
            .filter_map(|(ext, handle)| handle.cisco_frr().map(|(c, _, _, _)| (ext, c)))
        {
            if !sessions.contains_key(ext) {
                log::error!(
                    "No SSH session created for physical external router {} (on {})",
                    ext.fmt(self.net),
                    c.ssh_name
                );
                return Err(RouterLabError::Network(NetworkError::DeviceNotFound(*ext)));
            }
        }
        Ok(sessions)
    }
}

impl<'n, P: Prefix, Q, Ospf: OspfImpl, S> RouterLab<'n, P, Q, Ospf, S> {
    /// Get the router SSH host name that is associated with the given router ID. If the router ID
    /// is not an internal router, this function will return a `NetworkError`.
    pub fn get_router_device(&self, router: RouterId) -> Result<&'static str, RouterLabError> {
        Ok(self
            .routers
            .get(&router)
            .map(|(i, _)| i.ssh_name.as_str())
            .ok_or_else(|| NetworkError::DeviceNotFound(router))?)
    }

    /// Get the `RouterProperties` corresponding to the `router`. Contains the `ssh_name`,
    /// `mgnt_addr` and a list of connected `RouterIface`. If the router ID does not correspond to
    /// a pyhsical router, this function will return a `NetworkError`.
    pub fn get_router_properties(
        &self,
        router: RouterId,
    ) -> Result<&'static RouterProperties, RouterLabError> {
        Ok(self
            .routers
            .get(&router)
            .map(|(i, _)| i)
            .or(self
                .external_routers
                .get(&router)
                .and_then(|handle| handle.cisco_frr().map(|(vdc, _, _, _)| vdc))
                .as_ref())
            .ok_or_else(|| NetworkError::DeviceNotFound(router))?)
    }

    /// Get the interface configurations used by the prober, e.g., to automatically search through
    /// captured monitoring traffic and detect changes in the forwarding state precisely.
    ///
    /// For each `RouterId`, contains the tofino port used, the router-side MAC address of the
    /// prober interface, and the source IP for prober traffic to be expected on this interface.
    pub fn get_prober_ifaces(&self) -> &HashMap<RouterId, (usize, [u8; 6], Ipv4Addr)> {
        &self.prober_ifaces
    }

    /// Get a mutable reference to the configuration generator of a specific router. If the router
    /// does not exist or is not an internal router, this function will return a
    /// `NetworkError`. This function will also return a mutable reference to the addressor.
    #[allow(clippy::type_complexity)]
    pub fn get_router_cfg_gen(
        &mut self,
        router: RouterId,
    ) -> Result<
        (
            &mut CiscoFrrCfgGen<P>,
            &mut DefaultAddressor<'n, P, Q, Ospf>,
        ),
        RouterLabError,
    > {
        let cfg_gen = self
            .routers
            .get_mut(&router)
            .map(|(_, x)| x)
            .ok_or_else(|| NetworkError::DeviceNotFound(router))?;
        Ok((cfg_gen, &mut self.addressor))
    }
}

impl<'n, P: Prefix, Q: EventQueue<P> + Clone, Ospf: OspfImpl, S> RouterLab<'n, P, Q, Ospf, S> {
    /// Generate the configuration for a physical router in the network. This function will
    /// return the configuration as a string.
    pub fn generate_router_config(&mut self, router: RouterId) -> Result<String, RouterLabError> {
        let (vdc, gen) = self
            .routers
            .get_mut(&router)
            // move reference out of the tuple for type compatibility
            .map(|(a, b): &mut (&'static RouterProperties, CiscoFrrCfgGen<P>)| (a, b))
            .xor(self.external_routers.iter_mut().find_map(|(ext, handle)| {
                if *ext == router {
                    if let ExternalRouterHandle::CiscoFrr(
                        vdc,
                        cisco_frr_gen,
                        _exabgp_info,
                        _routes,
                    ) = handle
                    {
                        return Some((vdc, cisco_frr_gen));
                    }
                }
                None
            }))
            .ok_or_else(|| NetworkError::DeviceNotFound(router))?;

        let ssh_name = vdc.ssh_name.clone();

        // check if an interface of that router is not yet used.
        let ifaces = self.addressor.list_ifaces(router);
        // find the last interface that is not yes used
        let unused_iface = (0..vdc.ifaces.len())
            .rev()
            .find(|iface| ifaces.iter().all(|(_, _, _, i)| i != iface))
            .map(|unused_iface_id| {
                (
                    // iface_id
                    unused_iface_id,
                    // iface_name
                    vdc.ifaces[unused_iface_id].iface.as_str(),
                    // iface_mac
                    vdc.ifaces[unused_iface_id].mac,
                )
            });

        if self.net.get_device(router)?.is_internal() {
            // first, generate the basic config string for internal routers
            let mut config = InternalCfgGen::generate_config(gen, self.net, &mut self.addressor)?;

            // get an interface that is not yet used
            if let Some((prober_iface, iface_name, iface_mac)) = unused_iface {
                // check that the interface has not been configured yet
                assert!(!config.contains(iface_name));

                // create prober interface
                let network = self.addressor.router_network(router)?;
                let src_addr = network
                    .hosts()
                    .nth(5)
                    .ok_or(ExportError::NotEnoughAddresses)?;
                let iface_addr = network.hosts().nth(4).expect("already checked");

                // store the interface
                if let Some((stored_iface, stored_mac, stored_addr)) =
                    self.prober_ifaces.get(&router)
                {
                    if stored_iface != &prober_iface
                        || stored_mac != &iface_mac
                        || stored_addr != &src_addr
                    {
                        log::warn!(
                        "[{}] Computed prober interface does not match the value previously computed!",
                        ssh_name
                    );
                    }
                } else {
                    log::debug!(
                    "[{ssh_name}] Using interface {iface_name} with IP {iface_addr} for prober packets on {}, set source IP to {src_addr}",
                    router.fmt(self.net),
                );
                }
                self.prober_ifaces
                    .insert(router, (prober_iface, iface_mac, src_addr));

                // generate the configuration
                config.push_str("!\n! Interface for the prober\n!\n");
                config.push_str(
                    &Interface::new(iface_name)
                        .no_switchport()
                        .ip_address(
                            Ipv4Net::new(iface_addr, CONFIG.addresses.link_prefix_len).unwrap(),
                        )
                        .mac_address(iface_mac)
                        .no_shutdown()
                        .build(CiscoNexus7000),
                );
            } else {
                // no dedicated interface available for prober traffic
                let (neighbor, addr, _, iface) = *ifaces.first().unwrap();
                let mac = vdc.ifaces[iface].mac;

                // store the interface
                if let Some((stored_iface, stored_mac, stored_addr)) =
                    self.prober_ifaces.get(&router)
                {
                    if stored_iface != &iface || stored_mac != &mac || stored_addr != &addr {
                        log::warn!(
                        "[{ssh_name}] Computed prober interface does not match the value previously computed!",
                    );
                    }
                } else {
                    log::warn!(
                    "[{ssh_name}] not enough addresses for dedicated prober interface on {}, using interface towards {} instead!",
                    router.fmt(self.net),
                    neighbor.fmt(self.net),
                );
                }
                self.prober_ifaces.insert(router, (iface, mac, addr));
            }

            Ok(config)
        } else {
            // first, generate the basic config string for external routers, but remove its locally
            // advertised routes
            let mut modified_net = self.net.clone();
            // do not propagate changes as we only use this network to generate the configs
            modified_net.manual_simulation();

            // remove original advertisements as otherwise router-lab would advertise them locally
            // from the physical external router
            let advertised_prefixes: Vec<_> = modified_net
                .get_external_router(router)?
                .advertised_prefixes()
                .copied()
                .collect();
            for prefix in advertised_prefixes {
                modified_net.withdraw_external_route(router, prefix)?;
            }
            let mut config =
                ExternalCfgGen::generate_config(gen, &modified_net, &mut self.addressor)?;

            let Some(ExternalRouterHandle::CiscoFrr(
                _vdc,
                _cisco_frr_gen,
                Some(exabgp_info),
                _routes,
            )) = self.external_routers.get(&router)
            else {
                panic!("ExternalRouterHandle for physical external router was not properly initialized.");
            };

            // get an interface that is not yet used
            if let Some((_exabgp_iface, iface_name, iface_mac)) = unused_iface {
                // check that the interface has not been configured yet
                assert!(!config.contains(iface_name));
                // create exabgp interface for physical external routers
                config.push_str("!\n! Interface for the exabgp connection\n!\n");
                config.push_str(
                    &Interface::new(iface_name)
                        .no_switchport()
                        .ip_address(
                            Ipv4Net::new(exabgp_info.router_ip, CONFIG.addresses.link_prefix_len)
                                .unwrap(),
                        )
                        .mac_address(iface_mac)
                        .no_shutdown()
                        .build(CiscoNexus7000),
                );

                // configure route-maps for the exabgp connection on a physical external router
                config.push_str("!\n! Route-maps for the exabgp connection\n!\n");
                config.push_str(
                    &RouteMapItem::new("exabgp-in", u16::MAX, true).build(CiscoNexus7000),
                );
                config.push_str(
                    &RouteMapItem::new("exabgp-out", u16::MAX, true).build(CiscoNexus7000),
                );

                // configure bgp session for exabgp on a physical external router
                config.push_str("!\n! BGP session for the exabgp connection\n!\n");
                config.push_str(
                    &RouterBgp::new(exabgp_info.router_as)
                        .neighbor(
                            RouterBgpNeighbor::new(exabgp_info.exabgp_ip)
                                .update_source(iface_name)
                                .remote_as(exabgp_info.exabgp_as)
                                .next_hop_self()
                                .route_map_in("exabgp-in")
                                .route_map_out("exabgp-out"),
                        )
                        .build(CiscoNexus7000),
                );
            } else {
                // no dedicated interface available for an exabgp connection
                log::warn!(
                    "[{ssh_name}] not enough interfaces for a dedicated exabgp interface on {}!",
                    router.fmt(self.net),
                );
            }

            Ok(config)
        }
    }

    /// Get the configuration of all physical routers, including their associated SSH host name.
    pub fn generate_router_config_all(
        &mut self,
    ) -> Result<BTreeMap<RouterId, (&'static str, String)>, RouterLabError> {
        self.routers
            .iter()
            .map(|(r, (vdc, _))| (*r, vdc.ssh_name.as_str()))
            // append physical external routers
            .chain(self.external_routers.iter().filter_map(|(ext, handle)| {
                if let ExternalRouterHandle::CiscoFrr(vdc, _cisco_frr_gen, _exabgp_info, _routes) =
                    handle
                {
                    return Some((*ext, vdc.ssh_name.as_str()));
                }
                None
            }))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(r, ssh_name)| Ok((r, (ssh_name, self.generate_router_config(r)?))))
            .collect()
    }
}

impl<'n, P: Prefix, Q: EventQueue<P> + Clone, Ospf: OspfImpl> RouterLab<'n, P, Q, Ospf, Active> {
    pub(crate) async fn configure_routers(&mut self) -> Result<(), RouterLabError> {
        log::info!("Configure all routers");

        let mut config = self.generate_router_config_all()?;

        for job in self
            .state
            .routers
            .iter()
            .map(|(r, s)| (s.clone(), config.remove(r).unwrap()))
            .map(|(handle, (_, config))| {
                tokio::spawn(async move {
                    let mut sh = handle.shell();
                    sh.configure(config).await?;
                    Ok(())
                })
            })
            .collect::<Vec<JoinHandle<Result<(), RouterLabError>>>>()
        {
            job.await??;
        }

        Ok(())
    }
}

impl<'n, P: Prefix, Q, Ospf: OspfImpl> RouterLab<'n, P, Q, Ospf, Active> {
    /// Clear all the routers' ARP caches.
    pub(crate) async fn clear_router_arp_caches(&self) -> Result<(), RouterLabError> {
        log::info!("Clear ARP cache on all routers");

        for job in self
            .state
            .routers
            .values()
            .cloned()
            .map(|h| tokio::spawn(async move { h.clear_arp_cache().await }))
        {
            job.await??;
        }

        Ok(())
    }

    /// Get a SessionHandle of a router SSH session.
    pub fn get_router_session(&self, router: RouterId) -> Result<CiscoSession, RouterLabError> {
        Ok(self
            .state
            .routers
            .get(&router)
            .ok_or(NetworkError::DeviceNotFound(router))?
            .clone())
    }

    /// Apply a command to the network.
    pub async fn apply_command(&mut self, expr: ConfigModifier<P>) -> Result<(), RouterLabError> {
        log::info!("Apply {}", expr.fmt(self.net));

        for router in expr.routers() {
            if self.net.get_device(router)?.is_external() {
                log::warn!("Skipping reconfiguration on external router!");
                continue;
            }

            let cmd = self.routers.get_mut(&router).unwrap().1.generate_command(
                self.net,
                &mut self.addressor,
                expr.clone(),
            )?;

            // get a shell
            let mut shell = self.state.routers[&router].shell();

            // execute the command
            shell.configure(cmd).await?;
        }

        Ok(())
    }

    /// Schedule a command to be applied to the network at a later time.
    pub fn apply_command_schedule(
        &mut self,
        expr: ConfigModifier<P>,
        delay: Duration,
    ) -> Result<(), RouterLabError> {
        let cmd_fmt = expr.fmt(self.net);
        let mut plan = HashMap::new();

        for router in expr.routers() {
            if self.net.get_device(router)?.is_external() {
                log::warn!("Skipping reconfiguration on external router!");
                continue;
            }

            let cmd = self.routers.get_mut(&router).unwrap().1.generate_command(
                self.net,
                &mut self.addressor,
                expr.clone(),
            )?;
            let handle = self.state.routers[&router].clone();

            plan.insert(router, (cmd, handle));
        }

        tokio::task::spawn(async move {
            tokio::time::sleep(delay).await;
            log::info!("Apply {cmd_fmt}");
            for (cmd, handle) in plan.into_values() {
                let mut shell = handle.shell();
                match shell.configure(cmd).await {
                    Ok(_) => {}
                    Err(e) => log::error!("[{}] Cannot apply the command: {e}", handle.name()),
                }
            }
        });

        Ok(())
    }

    /// Check that the BGP state is equal to the provided network. Equality is checked by making
    /// sure every router selects the correct BGP next-hop for every destination prefix. Make sure
    /// that `net` has the same routers as `self.net`.
    pub async fn equal_bgp_state(
        &mut self,
        net: &Network<P, Q, Ospf>,
    ) -> Result<bool, RouterLabError> {
        let mut all_correct = true;
        for (router, exp_bgp_routes) in self.expected_bgp_state(Some(net))? {
            let mut shell = self.state.routers[&router].shell();
            if !shell.check_bgp_next_hop(&exp_bgp_routes).await? {
                log::warn!(
                    "{} ({}) has wrong BGP state!",
                    router.fmt(net),
                    self.get_router_device(router)?,
                );
                log::debug!("Expected state:\n{:#?}", exp_bgp_routes);
                log::debug!(
                    "Acquired state:\n{:#?}",
                    shell
                        .get_bgp_routes()
                        .await?
                        .into_iter()
                        .filter(|(n, _)| exp_bgp_routes.contains_key(n))
                        .filter_map(|(n, r)| Some((n, r.into_iter().find(|r| r.selected)?)))
                        .collect::<HashMap<_, _>>()
                );
                all_correct = false;
            }
        }

        Ok(all_correct)
    }

    /// Wait for OSPF and BGP to converge. This function will wait until the following has occurred:
    ///
    /// 1. All OSPF neighbors are established
    /// 2. OSPF table does not change for 10 seconds
    /// 3. ALL BGP sessions are established
    /// 4. BGP table does not change for 10 seconds.
    ///
    /// This is done by using two channels. The first one is an MPSC channel that sends the updates
    /// from the router threads to the controller thread. The second one is a Broadcast channel used
    /// by the controller thread to trigger the next state of the workers.
    pub async fn wait_for_convergence(&mut self) -> Result<(), RouterLabError> {
        if cfg!(feature = "ignore-routers") {
            log::warn!("Skip convergence! (Feature `ignore-routers` is enabled)");
            return Ok(());
        }
        let (message_tx, mut message_rx) = mpsc::channel::<ConvergenceMessage>(1024);
        let (mut state_tx, state_rx) = broadcast::channel::<ConvergenceState>(1024);

        // compute the expected bgp state
        let mut exp_bgp_state = self.expected_bgp_state(None)?;

        log::info!("[convergence] Wait for convergence");
        let num_workers = self.routers.len();

        let mut workers = Vec::new();
        for (worker_id, (router, (cfg, _))) in self.routers.iter().enumerate() {
            // compute the expected OSPF state
            let exp_ospf_neighbors: HashSet<OspfNeighbor> = self
                .addressor
                // get all interfaces
                .list_ifaces(*router)
                .into_iter()
                // only care about the neighbor and the interface idx
                .map(|(n, _, _, iface)| (n, iface))
                // only care about internal routers
                .filter(|(n, _)| {
                    self.net
                        .get_device(*n)
                        .map(|r| r.is_internal())
                        .unwrap_or(false)
                })
                // get the router-id of the neighbor, and the address of its connected interface
                .map(|(n, iface)| {
                    let id = self.addressor.router_address(n)?;
                    let address = self.addressor.iface_address(n, *router)?;
                    Ok(OspfNeighbor {
                        id,
                        address,
                        iface: cfg.ifaces[iface].iface.clone(),
                    })
                })
                .collect::<Result<_, RouterLabError>>()?;

            let exp_bgp_routes = exp_bgp_state.remove(router).unwrap_or_default();

            // spawn the threads
            let child_message_tx = message_tx.clone();
            let child_state_rx = state_rx.resubscribe();

            let shell = self.state.routers[router].shell();
            // start the task
            workers.push(tokio::task::spawn(async move {
                shell
                    .wait_convergence_task(
                        worker_id,
                        num_workers,
                        exp_ospf_neighbors,
                        exp_bgp_routes,
                        child_message_tx,
                        child_state_rx,
                        ConvergenceState::OspfNeighbors,
                    )
                    .await
            }))
        }

        std::mem::drop(message_tx);
        std::mem::drop(state_rx);

        // call the controller
        self.wait_convergence_controller(&mut message_rx, &mut state_tx)
            .await?;

        // join all workers
        for worker in workers {
            // ignore errors occurring after the controller succeeded
            let _ = worker.await;
        }

        std::mem::drop(message_rx);
        std::mem::drop(state_tx);

        Ok(())
    }

    /// Wait until we don't see any new bgp updates within the given duration.
    pub async fn wait_for_no_bgp_messages(
        &mut self,
        duration: Duration,
    ) -> Result<(), RouterLabError> {
        if cfg!(feature = "ignore-routers") {
            log::warn!("Skip convergence! (Feature `ignore-routers` is enabled)");
            return Ok(());
        }
        let (message_tx, mut message_rx) = mpsc::channel::<ConvergenceMessage>(1024);
        let (mut state_tx, state_rx) = broadcast::channel::<ConvergenceState>(1024);

        // compute the expected bgp state
        let mut exp_bgp_state = self.expected_bgp_state(None)?;

        let num_workers = self.routers.len();
        let mut workers = Vec::new();
        for (worker_id, router) in self.routers.keys().enumerate() {
            let child_message_tx = message_tx.clone();
            let child_state_rx = state_rx.resubscribe();
            let exp_bgp_routes = exp_bgp_state.remove(router).unwrap_or_default();
            let shell = self.state.routers[router].shell();
            workers.push(tokio::task::spawn(async move {
                shell
                    .wait_convergence_task(
                        worker_id,
                        num_workers,
                        Default::default(),
                        exp_bgp_routes,
                        child_message_tx,
                        child_state_rx,
                        ConvergenceState::BgpState,
                    )
                    .await
            }))
        }

        std::mem::drop(message_tx);
        std::mem::drop(state_rx);

        // call the controller
        self.wait_no_bgp_messages(duration, &mut message_rx, &mut state_tx)
            .await?;

        // join all workers
        for worker in workers {
            // ignore errors occurring after the controller succeeded
            let _ = worker.await;
        }

        std::mem::drop(message_rx);
        std::mem::drop(state_tx);

        Ok(())
    }

    /// Partly run the controller for waiting for convergence, only waiting to observe no changes
    /// in the BGP states of the routers.
    async fn wait_no_bgp_messages(
        &self,
        delay: Duration,
        message_rx: &mut mpsc::Receiver<ConvergenceMessage>,
        state_tx: &mut broadcast::Sender<ConvergenceState>,
    ) -> Result<(), RouterLabError> {
        let deadline = Duration::from_secs(30 * 60);
        let start_time = Instant::now();

        log::info!("[convergence] Wait for BGP to stop sending messages.");

        self.wait_convergence_no_message(
            message_rx,
            ConvergenceState::BgpState,
            deadline,
            start_time,
            delay,
        )
        .await?;
        state_tx
            .send(ConvergenceState::Done)
            .map_err(|_| RouterLabError::ConvergenceError)?;

        log::info!(
            "[convergence] Network has converged after {} seconds",
            start_time.elapsed().as_secs()
        );

        Ok(())
    }

    /// Listen to the monitoring interface for no BGP messages for some time.
    pub async fn wait_for_no_bgp_messages_on_monitoring_iface(
        &self,
        delay: Duration,
    ) -> Result<(), RouterLabError> {
        let start_time = Instant::now();

        log::info!(
            "[convergence] Wait for BGP to stop sending messages on {}.",
            CONFIG.server.traffic_monitor_iface
        );

        let result = Command::new("ssh")
            .args([
                "-t",
                &CONFIG.server.ssh_name,
                &format!(
                    "while read -t {} line; do echo -n \"\"; done < <(sudo tcpdump -i {} \"port 179 and len > 85\" 2>/dev/null)",
                    delay.as_secs(),
                    CONFIG.server.traffic_monitor_iface,
                ),
            ])
            .output()
            .await?;
        log::trace!("{result:?}");

        log::info!(
            "[convergence] Network has converged after {} seconds",
            start_time.elapsed().as_secs()
        );

        Ok(())
    }

    /// Main controller for waiting for convergence
    async fn wait_convergence_controller(
        &self,
        message_rx: &mut mpsc::Receiver<ConvergenceMessage>,
        state_tx: &mut broadcast::Sender<ConvergenceState>,
    ) -> Result<(), RouterLabError> {
        let deadline = Duration::from_secs(30 * 60);
        let start_time = Instant::now();

        log::info!("[convergence] Wait for OSPF to establish neighbors");

        // first, wait for done messages
        self.wait_convergence_done_messages(
            message_rx,
            ConvergenceState::OspfNeighbors,
            deadline,
            start_time,
        )
        .await?;
        state_tx
            .send(ConvergenceState::OspfState)
            .map_err(|_| RouterLabError::ConvergenceError)?;

        log::info!("[convergence] Wait for OSPF to converge");

        // then, wait for no update message in ospf state
        self.wait_convergence_no_message(
            message_rx,
            ConvergenceState::OspfState,
            deadline,
            start_time,
            Duration::from_secs(OSPF_CONVERGENCE_THRESHOLD_SECS),
        )
        .await?;
        state_tx
            .send(ConvergenceState::BgpNeighbors)
            .map_err(|_| RouterLabError::ConvergenceError)?;

        log::info!("[convergence] Wait for BGP to establish neighbors");

        // Then, wait for all BGP sessions to connect
        self.wait_convergence_done_messages(
            message_rx,
            ConvergenceState::BgpNeighbors,
            deadline,
            start_time,
        )
        .await?;
        state_tx
            .send(ConvergenceState::BgpNextHop)
            .map_err(|_| RouterLabError::ConvergenceError)?;

        log::info!("[convergence] Wait for BGP to reach the desired state");

        // Then, wait for all BGP sessions to connect
        self.wait_convergence_done_messages(
            message_rx,
            ConvergenceState::BgpNextHop,
            deadline,
            start_time,
        )
        .await?;
        state_tx
            .send(ConvergenceState::BgpState)
            .map_err(|_| RouterLabError::ConvergenceError)?;

        log::info!("[convergence] Wait for BGP to converge");

        // Finally, wait for BGP to converge
        self.wait_convergence_no_message(
            message_rx,
            ConvergenceState::BgpState,
            deadline,
            start_time,
            Duration::from_secs(BGP_CONVERGENCE_THRESHOLD_SECS),
        )
        .await?;
        state_tx
            .send(ConvergenceState::Done)
            .map_err(|_| RouterLabError::ConvergenceError)?;

        log::info!(
            "[convergence] Network has converged after {} seconds",
            start_time.elapsed().as_secs()
        );

        /*
        for (rid, cisco_session) in self.state.routers.iter() {
            log::trace!(
                "[convergence] BGP state of router {} after convergence:\n{}",
                rid.fmt(self.net),
                cisco_session.show("ip bgp all").await?
            );
        }
        */

        Ok(())
    }

    async fn wait_convergence_done_messages(
        &self,
        message_rx: &mut mpsc::Receiver<ConvergenceMessage>,
        state: ConvergenceState,
        deadline: Duration,
        start_time: Instant,
    ) -> Result<(), RouterLabError> {
        let mut seen_messages = HashSet::new();

        while seen_messages.len() < self.routers.len() {
            let until_deadline = deadline.saturating_sub(start_time.elapsed());
            match timeout(until_deadline, message_rx.recv()).await {
                // timeout occurred
                Err(_) => {
                    log::warn!(
                        "[convergence] Timeout occurred while waiting for convergence in state {:?}",
                        state
                    );
                    return Err(RouterLabError::ConvergenceTimeout);
                }
                // Channels closed
                Ok(None) => {
                    log::warn!(
                        "[convergence] MPSC channel for receiving messages has no senders left!",
                    );
                    return Err(RouterLabError::ConvergenceError);
                }
                // received message from correct state
                Ok(Some(ConvergenceMessage(s, i))) if s == state => {
                    log::debug!("[convergence] Received message from {}", i);
                    seen_messages.insert(i);
                }
                // received message from wrong state
                Ok(Some(ConvergenceMessage(s, i))) => {
                    log::debug!(
                        "[convergence] Received message from {} in old state {:?}. Ignore the message",
                        i,
                        s
                    );
                }
            }
        }

        Ok(())
    }

    async fn wait_convergence_no_message(
        &self,
        message_rx: &mut mpsc::Receiver<ConvergenceMessage>,
        state: ConvergenceState,
        deadline: Duration,
        start_time: Instant,
        threshold: Duration,
    ) -> Result<(), RouterLabError> {
        let mut last_update = Instant::now();
        while start_time.elapsed() < deadline {
            let until_threshold = threshold.saturating_sub(last_update.elapsed());
            match timeout(until_threshold, message_rx.recv()).await {
                // If the timeout was reached, we can proceed
                Err(_) => {
                    log::debug!("[convergence] No update from workers received! Transition to the next state");
                    return Ok(());
                }
                // channels broke down.
                Ok(None) => {
                    log::warn!(
                        "[convergence] MPSC channel for receiving messages has no senders left!",
                    );
                    return Err(RouterLabError::ConvergenceError);
                }
                // received message from correct state
                Ok(Some(ConvergenceMessage(s, i))) if s == state => {
                    log::debug!("[convergence] Received message from {}", i);
                    last_update = Instant::now();
                }
                // received message from wrong state
                Ok(Some(ConvergenceMessage(s, i))) => {
                    log::debug!(
                        "[convergence] Received message from {} in old state {:?}. Ignore the message",
                        i,
                        s
                    );
                }
            }
        }

        log::warn!(
            "[convergence] Timeout occurred while waiting for convergence in state {:?}",
            state
        );
        Err(RouterLabError::ConvergenceTimeout)
    }

    /// Compute the expected BGP state, which is a list of routes and their expected BGP next-hop
    /// for each router in the network.
    ///
    /// If the argument `net` is `Some(net)`, then use this network as reference for what next-hop
    /// we expect. Otherwise, use `self.net`.
    fn expected_bgp_state(
        &mut self,
        net: Option<&Network<P, Q, Ospf>>,
    ) -> Result<HashMap<RouterId, HashMap<Ipv4Net, Option<Ipv4Addr>>>, ExportError> {
        let mut result = HashMap::new();

        let known_prefixes = self
            .net
            .get_known_prefixes()
            .chain(net.iter().flat_map(|n| n.get_known_prefixes()))
            .copied()
            .collect_vec();

        let net = net.unwrap_or(self.net);

        for router in self.routers.keys().copied() {
            if let Ok(r) = net.get_device(router).and_then(|x| x.internal_or_err()) {
                let mut exp_bgp_routes = HashMap::new();
                for p in known_prefixes.iter().copied() {
                    let nh = r
                        .bgp
                        .get_exact(p)
                        .map(|x| {
                            let nh = x.route.next_hop;
                            // check if nh is internal or external
                            if self.routers.contains_key(&nh) {
                                // router is internal. use router ip
                                self.addressor.router_address(nh)
                            } else {
                                // router is external. use interface ip
                                self.addressor.iface_address(nh, router)
                            }
                        })
                        .transpose()?;
                    for net in self.addressor.prefix(p)?.sample_uniform_n(BGP_PEC_CHECK) {
                        exp_bgp_routes.insert(*net, nh);
                    }
                }
                result.insert(router, exp_bgp_routes);
            }
        }

        Ok(result)
    }
}

/// Run `show module` on all routers (not on the vdcs) and make sure that the first supervisor
/// module status is set to `active *`, while the second one is set to `ha-standby`.
pub(crate) async fn check_router_ha_status() -> Result<(), RouterLabError> {
    for job in ROUTERS
        .iter()
        .map(String::as_str)
        .map(|x| tokio::spawn(_check_router_ha_status(x)))
        .collect::<Vec<_>>()
    {
        job.await??;
    }
    Ok(())
}

/// Run `show module` on `router` and make sure that the first supervisor module status is set to
/// `active *`, while the second one is set to `ha-standby`.
pub(crate) async fn _check_router_ha_status(router: &'static str) -> Result<(), RouterLabError> {
    log::debug!("[{router}] checking supervisor status.");

    #[derive(Deserialize)]
    struct ModInfo {
        #[serde(alias = "TABLE_modinfo")]
        table: ModInfoTable,
    }
    #[derive(Deserialize)]
    struct ModInfoTable {
        #[serde(alias = "ROW_modinfo")]
        rows: Vec<ModInfoRow>,
    }
    #[derive(Deserialize)]
    struct ModInfoRow {
        #[serde(alias = "mod")]
        module: u32,
        modtype: String,
        status: String,
    }
    let ssh = SshSession::new(router).await?;
    let mod_info_json = ssh.execute_cmd_stdout(&["show module | json"]).await?;
    let mod_info: ModInfo = serde_json::from_str(&mod_info_json).map_err(|e| {
        RouterLabError::CannotParseShowModule({
            let mut error_msg = format!("[{router}] ");
            error_msg.push_str(&e.to_string());
            error_msg
        })
    })?;

    if let (Some(row_1), Some(row_2)) = (mod_info.table.rows.first(), mod_info.table.rows.get(1)) {
        if row_1.module != 1 || row_2.module != 2 {
            log::error!("[{router}] Unexpected numbering of modules in `show modules`!");
        } else if row_1.modtype != "Supervisor Module-2" || row_2.modtype != "Supervisor Module-2" {
            log::error!("[{router}] Module 1 and 2 on the device are not supervisors!");
        } else if row_1.status != "active *" || row_2.status != "ha-standby" {
            log::error!(
                "[{router}] Module 1 is in status `{}`, while module 2 is in status `{}`!",
                row_1.status,
                row_2.status
            )
        } else {
            log::trace!("[{router}] Supervisor status is correct!");
            return Ok(());
        }
    } else {
        log::error!("[{router}] Router contains less than two supervisors!")
    }

    log::error!(
        "[{router}] Supervisor (high-availability) status is bad! Maybe restart the router?"
    );
    log::info!("[{router}] Hint: `ssh {router} reload`");

    Err(RouterLabError::WrongSupervisorStatus(router.to_string()))
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ConvergenceState {
    OspfNeighbors,
    OspfNeighborsDone,
    OspfState,
    BgpNeighbors,
    BgpNeighborsDone,
    BgpNextHop,
    BgpNextHopDone,
    BgpState,
    Done,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct ConvergenceMessage(ConvergenceState, usize);

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

//! This module is responsible for managing the server in the Router-Lab setup. It manages the ExaBGP
//! process, as well as the physical interface setup, and generating or capturing traffic.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsStr,
    fmt::Write,
    io::Write as IoWrote,
    net::Ipv4Addr,
    path::PathBuf,
    time::Duration,
};

use bgpsim::{
    export::{Addressor, ExaBgpCfgGen, ExportError, ExternalCfgGen},
    prelude::*,
    types::PrefixMap,
};
use ipnet::Ipv4Net;
use itertools::Itertools;
use rand::{seq::SliceRandom, thread_rng};
use time::{format_description, OffsetDateTime};

mod cmd;
mod exabgp;
mod session;
pub(crate) mod traffic_capture;

use bgpsim::export::{cisco_frr_generators::Target::CiscoNexus7000, CiscoFrrCfgGen};
pub use cmd::{CmdError, CmdHandle};
pub use exabgp::ExaBgpHandle;
pub use session::ServerSession;
pub use traffic_capture::{CaptureSample, TrafficCaptureError, TrafficCaptureHandle, TrafficFlow};

use crate::{
    config::{CONFIG, VDCS},
    ssh::SshSession,
    Active, RouterLab, RouterLabError, Inactive, RouterProperties,
};

pub type Capture<P> = HashMap<(RouterId, P, Ipv4Addr), Vec<(f64, f64, RouterId, u64)>>;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ExternalRouterHandle<P: Prefix> {
    ExaBgp(ExaBgpCfgGen<P>),
    CiscoFrr(
        &'static RouterProperties,
        CiscoFrrCfgGen<P>,
        Option<ExaBgpInfo>,
        Vec<BgpRoute<P>>,
    ),
}

impl<P: Prefix> ExternalRouterHandle<P> {
    pub fn is_exabgp(&self) -> bool {
        matches!(self, Self::ExaBgp(_exabgp_gen))
    }

    pub fn exabgp(&self) -> Option<&ExaBgpCfgGen<P>> {
        if let Self::ExaBgp(exabgp_gen) = self {
            Some(exabgp_gen)
        } else {
            None
        }
    }

    pub fn exabgp_mut(&mut self) -> Option<&mut ExaBgpCfgGen<P>> {
        if let Self::ExaBgp(ref mut exabgp_gen) = self {
            Some(exabgp_gen)
        } else {
            None
        }
    }

    pub fn is_cisco_frr(&self) -> bool {
        matches!(
            self,
            Self::CiscoFrr(_vdc, _cisco_frr_gen, _exabgp_info, _routes)
        )
    }

    #[allow(clippy::type_complexity)]
    pub fn cisco_frr(
        &self,
    ) -> Option<(
        &'static RouterProperties,
        &CiscoFrrCfgGen<P>,
        &Option<ExaBgpInfo>,
        &Vec<BgpRoute<P>>,
    )> {
        if let Self::CiscoFrr(vdc, cisco_frr_gen, exabgp_info, routes) = self {
            Some((vdc, cisco_frr_gen, exabgp_info, routes))
        } else {
            None
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn cisco_frr_mut(
        &mut self,
    ) -> Option<(
        &'static RouterProperties,
        &mut CiscoFrrCfgGen<P>,
        &mut Option<ExaBgpInfo>,
        &mut Vec<BgpRoute<P>>,
    )> {
        if let Self::CiscoFrr(vdc, ref mut cisco_frr_gen, ref mut exabgp_info, ref mut routes) =
            self
        {
            Some((vdc, cisco_frr_gen, exabgp_info, routes))
        } else {
            None
        }
    }

    pub fn try_get_exabgp_info(&self) -> Option<ExaBgpInfo> {
        if let Self::CiscoFrr(_vdc, _cisco_frr_gen, Some(exabgp_info), _routes) = self {
            Some(*exabgp_info)
        } else {
            None
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ExaBgpInfo {
    pub exabgp_router_id: Ipv4Addr,
    pub exabgp_ip: Ipv4Addr,
    pub exabgp_as: AsId,
    pub router_ip: Ipv4Addr,
    pub router_as: AsId,
}

impl ExaBgpInfo {
    fn generate_config(&self) -> String {
        format!(
            "\
neighbor {} {{
    router-id {};
    local-address {};
    local-as {};
    peer-as {};
    family {{ ipv4 unicast; }}
    capability {{ route-refresh; }}
}}",
            self.router_ip,
            self.exabgp_router_id,
            self.exabgp_ip,
            self.exabgp_as.0,
            self.router_as.0,
        )
    }
}

impl<'n, P: Prefix, Q, Ospf: OspfImpl> RouterLab<'n, P, Q, Ospf, Inactive> {
    /// Prepare all external routers (used in the constructor of `RouterLab`).
    pub(super) fn prepare_external_routers(
        net: &'n Network<P, Q, Ospf>,
        external_binding: &HashMap<RouterId, impl AsRef<str>>,
    ) -> Result<BTreeMap<RouterId, ExternalRouterHandle<P>>, RouterLabError> {
        let mut result: Vec<Result<(RouterId, ExternalRouterHandle<P>), RouterLabError>> =
            Default::default();

        for (r, vdc_name) in external_binding {
            let vdc_name = vdc_name.as_ref();
            let Some(vdc) = VDCS.iter().find(|x| x.ssh_name.as_str() == vdc_name) else {
                return Err(RouterLabError::UnknownVdc(vdc_name.to_string()));
            };

            result.push(Ok((
                *r,
                Self::prepare_physical_external_router(net, *r, vdc)?,
            )));
        }
        result.extend(
            net.external_indices()
                // external routers with a binding to a physical device have been set up already
                .filter(|r| !external_binding.contains_key(r))
                .map(|r| Ok((r, ExternalRouterHandle::ExaBgp(ExaBgpCfgGen::new(net, r)?)))),
        );

        result.into_iter().collect()
    }

    fn prepare_physical_external_router(
        net: &'n Network<P, Q, Ospf>,
        r: RouterId,
        vdc: &'static RouterProperties,
    ) -> Result<ExternalRouterHandle<P>, RouterLabError> {
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

        Ok(ExternalRouterHandle::CiscoFrr(vdc, gen, None, vec![]))
    }
}

impl<'n, P: Prefix, Q, Ospf: OspfImpl, S> RouterLab<'n, P, Q, Ospf, S> {
    /// Generate the configuration for exabgp
    pub fn generate_exabgp_config(&mut self) -> Result<String, RouterLabError> {
        let mut c = format!(
            "process announce-routes {{\n    run /usr/bin/env python3 {};\n    encoder json;\n}}\n\n",
            CONFIG.server.exabgp_runner_filename,
        );

        // assign subnets for additional external routers from the back
        let iface_nets = self
            .addressor
            .subnet_for_external_links()
            .subnets(CONFIG.addresses.link_prefix_len)
            .unwrap();
        let mut rev_link_subnets = iface_nets.collect_vec().into_iter().rev();
        // skip last address as it is reserved for the interface address of the server
        let _last_addr = rev_link_subnets.next().unwrap().hosts().next().unwrap();

        for (ext, handle) in self.external_routers.iter_mut() {
            match handle {
                ExternalRouterHandle::ExaBgp(exabgp_gen) => {
                    c.push_str(&exabgp_gen.generate_config(self.net, &mut self.addressor)?);
                }
                ExternalRouterHandle::CiscoFrr(
                    _vdc,
                    _cisco_frr_gen,
                    ref mut exabgp_info,
                    _routes,
                ) => {
                    if exabgp_info.is_none() {
                        // assign network for exabgp to talk to physical external router
                        let external_link_net = rev_link_subnets.next().unwrap();
                        let mut link_addrs = external_link_net.hosts();
                        let exabgp_ip = link_addrs.next().unwrap();
                        let router_ip = link_addrs.next().unwrap();
                        let asid = self.net.get_external_router(*ext).unwrap().as_id();

                        *exabgp_info = Some(ExaBgpInfo {
                            exabgp_router_id: exabgp_ip,
                            exabgp_ip,
                            exabgp_as: asid,
                            router_ip,
                            router_as: asid,
                        });
                    }
                    c.push_str(&exabgp_info.as_ref().unwrap().generate_config());
                }
            }
            c.push('\n');
        }

        Ok(c)
    }

    /// Generate the configuration for netplan to work with exabgp
    pub fn generate_exabgp_netplan_config(&mut self) -> Result<String, RouterLabError> {
        let iface_nets = self
            .addressor
            .subnet_for_external_links()
            .subnets(CONFIG.addresses.link_prefix_len)
            .unwrap();
        let mut rev_link_subnets = iface_nets.collect_vec().into_iter().rev();
        let last_addr = rev_link_subnets.next().unwrap().hosts().next().unwrap();
        let iface_addr = Ipv4Net::new(last_addr, CONFIG.addresses.link_prefix_len).unwrap();

        let mut c = String::new();
        writeln!(&mut c, "network:")?;
        writeln!(&mut c, "  version: 2")?;
        writeln!(&mut c, "  renderer: networkd")?;
        writeln!(&mut c, "  ethernets:")?;
        writeln!(&mut c, "    {}:", CONFIG.server.exabgp_iface)?;
        writeln!(&mut c, "      link-local: []")?;
        writeln!(&mut c, "      dhcp4: no")?;
        writeln!(&mut c, "      dhcp6: no")?;
        writeln!(&mut c, "      addresses:")?;
        writeln!(&mut c, "        - {iface_addr}")?;

        let mut label_idx: usize = 0;
        for (r, ext) in self.external_routers.iter() {
            match ext {
                ExternalRouterHandle::ExaBgp(exabgp_gen) => {
                    for n in exabgp_gen.neighbors() {
                        writeln!(
                            &mut c,
                            "        - {}:\n            label: {}:{label_idx}",
                            self.addressor.iface_address_full(*r, *n)?,
                            CONFIG.server.exabgp_iface,
                        )?;
                        label_idx += 1;
                    }
                }
                ExternalRouterHandle::CiscoFrr(_vdc, _cisco_frr_gen, exabgp_info, _routes) => {
                    // create virtual interface dedicated to talk to physical external router
                    writeln!(
                        &mut c,
                        "        - {}:\n            label: {}:{label_idx}",
                        Ipv4Net::new(
                            exabgp_info.as_ref().unwrap().exabgp_ip,
                            CONFIG.addresses.link_prefix_len
                        )
                        .unwrap(),
                        CONFIG.server.exabgp_iface,
                    )?;
                    label_idx += 1;
                }
            }
        }

        Ok(c)
    }

    /// Generate the preamble of the python script to execute in exabgp, defining a function to
    /// `wait_until(t)` time t as indicated in the exabgp runner control file.
    pub fn generate_exabgp_runner_preamble(&self) -> Result<String, RouterLabError> {
        let mut s = String::from(
            "#!/usr/bin/env python3\nimport sys\nimport time\nfrom os.path import expanduser as full\n\n",
        );

        // write the function to wait until
        let c = CONFIG.server.exabgp_runner_control_filename.as_str();
        writeln!(&mut s, "def wait_until(x):")?;
        writeln!(&mut s, "    while True:")?;
        writeln!(&mut s, "        try:")?;
        writeln!(&mut s, "            with open(full('{c}'), 'r') as f:")?;
        writeln!(&mut s, "                t = int(f.read())")?;
        writeln!(&mut s, "                if t >= x: return")?;
        writeln!(&mut s, "        except FileNotFoundError:")?;
        writeln!(&mut s, "            pass")?;
        writeln!(&mut s, "        except ValueError:")?;
        writeln!(&mut s, "            pass")?;
        writeln!(&mut s, "        time.sleep(0.1)")?;
        writeln!(&mut s)?;

        Ok(s)
    }

    /// Generate the python script to execute in exabgp
    pub fn generate_exabgp_runner(&mut self) -> Result<String, RouterLabError> {
        let mut s = self.generate_exabgp_runner_preamble()?;

        let mut lines: BTreeMap<Duration, Vec<String>> = BTreeMap::new();

        // physical external routers
        self.external_routers
            .iter()
            .filter_map(|(ext_rid, ext)| {
                ext.cisco_frr()
                    .map(|(_vdc, _cisco_frr_gen, exabgp_info, routes)| {
                        let exabgp_info = exabgp_info
                            .expect("ExaBgpInfo should have been initialized at this point!");
                        (
                            // advertise all routes that are configured in bgpsim and will be added
                            // for the event
                            self.net
                                .get_external_router(*ext_rid)
                                .expect("should be an external router")
                                .get_advertised_routes()
                                .iter()
                                .map(|(_prefix, route)| route)
                                .chain(routes.iter())
                                .map(move |route| {
                                    let mut route = route.clone();
                                    // remove one hop if advertising the own external AS as cisco
                                    // routers append it automatically
                                    if let Some(first_as) = route.as_path.first() {
                                        if *first_as == exabgp_info.router_as {
                                            route.as_path.remove(0);
                                        }
                                    }
                                    // replace further occurrences with a dummy AS num to avoid cisco
                                    // routers ignoring the route
                                    route.as_path = route
                                        .as_path
                                        .into_iter()
                                        .map(|x| {
                                            if x != exabgp_info.router_as {
                                                x
                                            } else {
                                                666.into()
                                            }
                                        })
                                        .collect();
                                    format!(
                                        "sys.stdout.write(\"neighbor {} {}\\n\")",
                                        exabgp_info.router_ip,
                                        bgpsim::export::exabgp::announce_route(&route)
                                    )
                                }),
                            Duration::from_secs(0),
                        )
                    })
            })
            .for_each(|(l, time)| lines.entry(time).or_default().extend(l));

        // exabgp routers
        self.external_routers
            .values()
            .filter_map(|ext| {
                ext.exabgp()
                    .map(|exabgp_gen| exabgp_gen.generate_lines(&mut self.addressor))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .for_each(|(l, time)| lines.entry(time).or_default().extend(l));

        for (time, lines) in lines {
            // add the newline
            writeln!(&mut s)?;

            let time = time.as_secs_f64();
            writeln!(&mut s, "wait_until({time})")?;

            // write all lines
            for line in lines {
                writeln!(&mut s, "{line}")?;
            }
            writeln!(&mut s, "sys.stdout.flush()")?;
        }

        writeln!(&mut s, "\nwait_until(1_000_000)")?;

        Ok(s)
    }

    /// Advance all external router generators in time. This can be used to create a BGP event. The
    /// step will always be equal to 1.
    ///
    /// The generated python runner works as follows: Before sending the BGP updates of a next
    /// round, it waits until the contorl file has stored a number that is larger or equal to the
    /// current step.
    pub fn step_external_time(&mut self) {
        let step = Duration::from_secs(1);
        self.external_routers
            .values_mut()
            .filter_map(ExternalRouterHandle::exabgp_mut)
            .for_each(|exabgp_gen| exabgp_gen.step_time(step));
    }

    /// Advertise an additional route. This will only change the python runner for exabgp that are
    /// generated in the future. If used together with [`RouterLab::step_external_time`], you can
    /// create an exabgp runner that will change its avertisements over time.
    ///
    /// For physical external routers, this will advertise the route to the physical external
    /// router via exabgp in the very beginning. By default, this would then be propagated to its
    /// peer.
    pub fn advertise_route(
        &mut self,
        router: RouterId,
        route: &BgpRoute<P>,
    ) -> Result<(), RouterLabError> {
        match self
            .external_routers
            .get_mut(&router)
            .ok_or_else(|| NetworkError::DeviceNotFound(router))?
        {
            ExternalRouterHandle::ExaBgp(exabgp_gen) => {
                exabgp_gen.advertise_route(self.net, &mut self.addressor, route)?;
            }
            ExternalRouterHandle::CiscoFrr(_, _, _, ref mut routes) => {
                routes.push(route.clone());
            }
        }
        Ok(())
    }

    /// Withdraw a previously advertised route. This will only change the python runner for exabgp
    /// that are generated in the future. If used together with [`RouterLab::step_external_time`],
    /// you can create an exabgp runner that will change its avertisements over time.
    ///
    /// *Warning*: Make sure that the route was advertised before.
    ///
    /// Physical external routers are not supported.
    pub fn withdraw_route(&mut self, router: RouterId, prefix: P) -> Result<(), RouterLabError> {
        if let ExternalRouterHandle::ExaBgp(exabgp_gen) = self
            .external_routers
            .get_mut(&router)
            .ok_or_else(|| NetworkError::DeviceNotFound(router))?
        {
            exabgp_gen.withdraw_route(self.net, &mut self.addressor, prefix)?;
        } else {
            unimplemented!(
                "this function is currently not supported for physical external routers"
            );
        }
        Ok(())
    }
}

impl<'n, P: Prefix, Q, Ospf: OspfImpl> RouterLab<'n, P, Q, Ospf, Active> {
    /// Function to get a session handle for the server. This handle will use the pre-established
    /// SSH connection as long as it is still available, After that, it will re-establish a new
    /// connection for each command.
    ///
    /// See [`crate::ssh::SshSession`] for how to use the server session.
    pub fn get_server_session(&self) -> SshSession {
        self.state.server.0.clone()
    }

    /// Function to get the the exabgp handle which is running exabgp.
    pub fn get_exabgp_handle(&mut self) -> &mut ExaBgpHandle {
        &mut self.state.exabgp
    }

    /// Configure netplan. This requires the configuration file to be writable as the current user,
    /// and that the command `sudo netplan apply` can be executed without asking for the root
    /// password.
    pub(crate) async fn configure_netplan(&mut self) -> Result<(), RouterLabError> {
        let cfg = self.generate_exabgp_netplan_config()?;
        self.state.server.configure_netplan(cfg).await?;
        Ok(())
    }

    /// Start an `iperf` client that will generate some basic data-plane traffic to a running
    /// `iperf` server instance.
    ///
    /// The `bitrate` specifies the amount of traffic to be generated, in 1 Gigabit/sec. The `udp`
    /// specifies whether to generate UDP traffic, or TCP traffic otherwise. Beware that `iperf`
    /// can achieve much higher bitrates for TCP than UDP.
    pub async fn start_iperf(
        &mut self,
        bitrate: u8,
        udp: bool,
    ) -> Result<CmdHandle, RouterLabError> {
        let cmd = if !CONFIG.server.iperf_client_running {
            format!(
                "iperf3 --bind {} {} --bitrate {}G --time 0 --client {}",
                &CONFIG.server.iperf_client_ip,
                if udp { "--udp" } else { "" },
                bitrate,
                &CONFIG.server.iperf_server_ip,
            )
        } else {
            "echo \"iperf already running.\"".to_string()
        };
        let mut handle = CmdHandle::new("iperf client", cmd, self.state.server.0.clone()).await?;
        handle.start().await?;
        Ok(handle)
    }

    /// Stop the `iperf` client.
    pub async fn stop_iperf(&mut self, handle: CmdHandle) -> Result<(), RouterLabError> {
        handle.stop().await?;
        Ok(())
    }

    /// Start a `tcpdump` process capturing all data-plane traffic on the `traffic_monitor_iface`.
    /// Requires that the config option `traffic_monitor_enable` is set to `true` and that the
    /// `traffic_monitor_tofino_port`, `traffic_monitor_iface`, and `traffic_monitor_pcap_path` are
    /// set correctly and exist. Pcap files will be called `{pcap_path}/{name}_{timestamp}.pcap`
    /// and stored on the server. Requires that the user can run `sudo tcpdump` without a password.
    ///
    /// `filter_iperf_traffic` controls whether to add an IP-based packet capture filter to omit
    /// traffic generated by using the `start_iperf` API. Useful for smaller-sized PCAPs.
    pub async fn start_traffic_monitor(
        &mut self,
        name: impl AsRef<str>,
        filter_iperf_traffic: bool,
    ) -> Result<(PathBuf, CmdHandle), RouterLabError> {
        let cur_time = OffsetDateTime::now_local()
            .unwrap_or_else(|_| OffsetDateTime::now_utc())
            .format(
                &format_description::parse("[year]-[month]-[day]_[hour]-[minute]-[second]")
                    .unwrap(),
            )
            .unwrap();

        let mut pcap_path = PathBuf::from(&CONFIG.server.traffic_monitor_pcap_path);
        pcap_path.push(format!("{}_{cur_time}.pcap", name.as_ref()));

        let filter = if filter_iperf_traffic {
            format!(
                "not src {} and not src {}",
                &CONFIG.server.iperf_client_ip, &CONFIG.server.iperf_server_ip,
            )
        } else {
            "".to_string()
        };

        // prepare the `tcpdump` command
        let cmd = format!(
            "sudo {} -i {} -w {} {} 2>>{}",
            &CONFIG.server.traffic_monitor_cmd,
            &CONFIG.server.traffic_monitor_iface,
            pcap_path.to_string_lossy(),
            filter,
            &CONFIG.server.traffic_monitor_log,
        );

        // create the persistent child process running `tcpdump`
        let mut handle =
            CmdHandle::new("traffic monitor", cmd, self.state.server.0.clone()).await?;
        handle.start().await?;

        Ok((pcap_path, handle))
    }

    /// Stop the `traffic_monitor`, returns an ssh handle to the server and a number of packets
    /// reported to be dropped by tcpdump (`traffic_monitor_cmd`).
    pub async fn stop_traffic_monitor(
        &mut self,
        handle: CmdHandle,
    ) -> Result<(SshSession, usize), RouterLabError> {
        let ssh = handle.stop().await?;
        // get number of packets lost
        let packets_dropped: usize = ssh
            .execute_cmd_stdout(&["tail -n 1", &CONFIG.server.traffic_monitor_log])
            .await?
            .replace(" packet dropped by kernel", "")
            .replace(" packets dropped by kernel", "")
            .trim()
            .parse()
            .map_err(TrafficCaptureError::ParseError)?;

        Ok((ssh, packets_dropped))
    }

    /// Start a capture that will test all routers and all destinations in the network. See
    /// [`TrafficCaptureHandle`] for more information on how the capture is created.
    ///
    /// The `frequency` captures the number of ping packets sent per second for each flow in the
    /// network. A flow is a tuple consisting of a source router and a target prefix. For each
    /// router and for each prefix, one such flow is created.
    ///
    /// If there are more than `num_probes` prefixes, the capture will probe the first, the last,
    /// and an equidistantly chosen set of prefixes.
    pub async fn start_capture(
        &mut self,
        num_probes: usize,
        frequency: u64,
        randomize: bool,
    ) -> Result<TrafficCaptureHandle, RouterLabError> {
        let mut prefixes: Vec<_> = self.get_prefix_ip_lookup()?.into_keys().collect();
        prefixes.sort();

        // ensure that our prober is not being overloaded by choosing at most k destinations
        let selected_prefixes = if randomize {
            // suppress clippy warning but preserve same type as in the other branch
            #[allow(clippy::map_clone)]
            prefixes
                .choose_multiple(&mut thread_rng(), num_probes)
                .map(|x| *x)
                .collect_vec()
        } else {
            choose_equidistant_k(num_probes, prefixes)
        };

        let flows: Vec<TrafficFlow> = self
            .prober_ifaces
            .values()
            .flat_map(|(_, mac, addr)| {
                selected_prefixes.iter().map(move |dst_ip| TrafficFlow {
                    src_mac: *mac,
                    src_ip: *addr,
                    dst_ip: *dst_ip,
                })
            })
            .collect();

        let mut handle = TrafficCaptureHandle::new(self.state.server.0.clone(), &flows).await?;
        handle.start(frequency).await?;
        Ok(handle)
    }

    /// Stop a packet capture and parse the results. The returned hashmap contains, for each
    /// `(source, prefix)` pair, a vector of samples, where each sample has the following fields:
    /// `(t_send, t_recv, ext, counter)`
    ///
    /// - `t_send`: Timestamp when the packet was sent by the prober.
    /// - `t_recv`: Timestamp when the packet was received by the collector.
    /// - `ext`: Router ID of the external router to whom the packet was sent.
    /// - `counter`: Index of the packet..
    ///
    /// This function returns a hash map that contains, as key, both the source router, the external
    /// prefix, and the actual destination IP address that was used. This allows you to distinguish
    /// multiple destinations for the same Prefix Equivalence Class.
    ///
    /// Samples that cannot be parsed are simply ignored.
    pub async fn stop_capture(
        &mut self,
        mut handle: TrafficCaptureHandle,
    ) -> Result<Capture<P>, RouterLabError> {
        handle.stop().await?;

        let selected_dst_ips: Vec<_> = handle
            .get_prober_config()
            .flows
            .iter()
            .map(|f| f.dst_ip)
            .collect();

        let prefix_lookup = self.get_prefix_ip_lookup()?;
        let int_lookup: HashMap<Ipv4Addr, RouterId> = self
            .prober_ifaces
            .iter()
            .map(|(r, (_, _, x))| (*x, *r))
            .collect();
        let ext_lookup = self.get_external_router_mac_lookup()?;

        let mut destinations: HashMap<P, Vec<Ipv4Addr>> = HashMap::new();
        prefix_lookup.iter().for_each(|(addr, p)| {
            if selected_dst_ips.contains(addr) {
                destinations.entry(*p).or_default().push(*addr);
            }
        });

        let mut results = HashMap::new();
        self.net.internal_indices().for_each(|r| {
            destinations.iter().for_each(|(p, addrs)| {
                addrs.iter().for_each(|addr| {
                    results.insert((r, *p, *addr), Vec::new());
                })
            })
        });

        for sample in handle.take_samples().await? {
            if let (Some(int), Some(prefix), Some(ext)) = (
                int_lookup.get(&sample.src_ip),
                prefix_lookup.get(&sample.dst_ip),
                ext_lookup.get(&sample.mac),
            ) {
                results
                    .get_mut(&(*int, *prefix, sample.dst_ip))
                    .unwrap()
                    .push((sample.send_time, sample.time, *ext, sample.counter));
            }
        }

        Ok(results)
    }

    /// Perform a step in external advertisements at runtime. This causes ExaBGP to update the
    /// routing inputs.
    pub async fn step_exabgp(&mut self) -> Result<(), RouterLabError> {
        Ok(ExaBgpHandle::step(&self.state.exabgp).await?)
    }

    /// Schedule a step in external advertisements at runtime. Once this triggers, ExaBGP will
    /// update the routing inptus. Do schedule two steps for the same time. The step value will
    /// remain consistent, even with multiple scheduled steps.
    pub fn step_exabgp_scheduled(&mut self, delay: Duration) -> Result<(), RouterLabError> {
        let session = self.state.exabgp.session.clone();
        tokio::task::spawn(async move {
            tokio::time::sleep(delay).await;
            log::info!("Perform step in external inputs!");
            match exabgp::read_step(&session).await {
                Ok(step) => match exabgp::write_step(&session, step + 1).await {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("[{}] Cannot perform an exabgp step! {e}", session.name())
                    }
                },
                Err(e) => log::error!(
                    "[{}] Cannot read the current exabgp step! {e}",
                    session.name()
                ),
            }
        });
        Ok(())
    }

    /// Compute the prefix lookup. In case of a preifx equivalence class, this function will return
    /// the first prefix, the last, and one in between.
    fn get_prefix_ip_lookup(&mut self) -> Result<HashMap<Ipv4Addr, P>, ExportError> {
        let mut lookup = HashMap::new();
        for p in self.net.get_known_prefixes() {
            match self.addressor.prefix(*p)? {
                bgpsim::export::MaybePec::Single(net) => {
                    lookup.insert(
                        net.hosts().next().ok_or(ExportError::NotEnoughAddresses)?,
                        *p,
                    );
                }
                bgpsim::export::MaybePec::Pec(_, mut networks) => {
                    networks.sort_by_cached_key(|n| n.to_string());
                    let n = networks.len();
                    let networks = match n {
                        0..=2 => networks,
                        _ => vec![networks[0], networks[n / 2], networks[n - 1]],
                    };
                    for net in networks {
                        lookup.insert(
                            net.hosts().next().ok_or(ExportError::NotEnoughAddresses)?,
                            *p,
                        );
                    }
                }
            }
        }
        Ok(lookup)
    }

    /// compute the router IP address lookup
    fn get_external_router_mac_lookup(
        &mut self,
    ) -> Result<HashMap<[u8; 6], RouterId>, ExportError> {
        self.net
            .external_indices()
            .flat_map(|ext| {
                self.addressor
                    .list_ifaces(ext)
                    .into_iter()
                    .map(move |(int, _, _, _)| (ext, int))
            })
            .collect_vec()
            .into_iter()
            .map(|(ext, int)| {
                let iface_idx = self.addressor.iface_index(int, ext)?;
                let iface = self.routers[&int]
                    .0
                    .ifaces
                    .get(iface_idx)
                    .ok_or(ExportError::NotEnoughInterfaces(int))?;
                Ok((iface.mac, ext))
            })
            .collect()
    }
}

/// Export the captured traffic to CSV files.
///
/// This function will first create a folder in `root` named `{root}/{name}_{timestamp}`. Then, it
/// will create files named `{src}-{prefix}-{addr}-{dst}.csv` that contains the timestamps and
/// sequence numbers of all packets that were captured. Here, `src` is the router name from where
/// the packets originate, `prefix` is the prefix using `P::From<Ipv4Net>`, `addr` is the `Ipv4Addr`
/// that was used in each packet as destination IP, and `dst` is the name of the external router
/// to which packets were forwarded.
///
/// Each file will contain comma-separated values. The first column stores the time when the packet
/// was received, and the second column stores the sequence number of that packet.
///
/// This function returns the path to the folder that was created.
pub fn export_capture_to_csv<P: Prefix, Q>(
    net: &Network<P, Q>,
    capture: &Capture<P>,
    root: impl AsRef<OsStr>,
    name: impl AsRef<str>,
) -> Result<PathBuf, std::io::Error> {
    let cur_time = OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(
            &format_description::parse("[year]-[month]-[day]_[hour]-[minute]-[second]").unwrap(),
        )
        .unwrap();
    let mut path = PathBuf::from(root.as_ref());
    path.push(format!("{}_{cur_time}", name.as_ref()));

    let mut idx = None;
    while path.exists() {
        let i = idx.unwrap_or(0) + 1;
        idx = Some(i);
        path.pop();
        path.push(format!("{}_{cur_time}_{i}", name.as_ref()));
    }
    std::fs::create_dir_all(&path)?;

    // write the measurement result to file
    for ((src, dst, addr), data) in capture {
        let prefix_str = dst.to_string().replace(['.', '/'], "_");
        let addr_str = addr.to_string().replace('.', "_");
        for ext in net.external_indices() {
            path.push(format!(
                "{}-{}-{}-{}.csv",
                src.fmt(net),
                prefix_str,
                addr_str,
                ext.fmt(net)
            ));
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)?;
            file.write_all(b"send_time,recv_time,sequence_num\n")?;
            file.write_all(
                data.iter()
                    .filter(|(_, _, e, _)| *e == ext)
                    .map(|(t_send, t_recv, _, k)| format!("{t_send},{t_recv},{k}"))
                    .join("\n")
                    .as_bytes(),
            )?;
            path.pop();
        }
    }
    Ok(path)
}

/// Choose up to `k` elements from a `Vec<T>`. If there are more than `k` elements, the result
/// will contain the first, last, and `k-2` equidistant elements from the `Vec<T>`.
pub fn choose_equidistant_k<T, I>(k: usize, xs: I) -> Vec<T>
where
    I: IntoIterator<Item = T>,
    I::IntoIter: ExactSizeIterator + DoubleEndedIterator,
{
    let mut xs = xs.into_iter();

    // check if more than k elements are given, requiring equidistant sampling
    let l = xs.len();
    if l > k {
        let last = xs.next_back();
        xs.next()
            .into_iter()
            .chain((0..k - 2).flat_map(|_| {
                // step: ceil( (l-1) / (k-1) ) - 1
                xs.nth((((l - 2) + (k - 2)) / (k - 1)) - 1)
            }))
            // manually add last item to ensure we have both the first and last item
            .chain(last)
            .collect()
    } else {
        xs.collect()
    }
}

#[cfg(test)]
mod test {
    use bgpsim::export::DefaultAddressorBuilder;

    use super::*;

    #[test]
    fn build_physical_external_router() {
        // build a simple network with one external router
        let mut net: Network<SimplePrefix, _> = Network::default();
        let r = net.add_router("r");
        let ext = net.add_external_router("ext", AsId(1000));
        net.add_link(r, ext).unwrap();
        net.set_bgp_session(r, ext, Some(BgpSessionType::EBgp))
            .unwrap();

        // call `prepare_external_routers` with a binding to a physical external router
        let external_binding = HashMap::from([(ext, &VDCS[0].ssh_name)]);
        let routers =
            RouterLab::prepare_internal_routers(&net, &HashMap::new(), &external_binding).unwrap();
        let external_routers = RouterLab::prepare_external_routers(&net, &external_binding).unwrap();

        let addressor = DefaultAddressorBuilder {
            internal_ip_range: CONFIG.addresses.internal_ip_range,
            external_ip_range: CONFIG.addresses.external_ip_range,
            local_prefix_len: CONFIG.addresses.local_prefix_len,
            link_prefix_len: CONFIG.addresses.link_prefix_len,
            external_prefix_len: CONFIG.addresses.external_prefix_len,
        }
        .build(&net)
        .unwrap();

        let mut lab = RouterLab {
            net: &net,
            addressor,
            routers,
            prober_ifaces: Default::default(),
            external_routers,
            link_delays: Default::default(),
            hardware_mapping: Default::default(),
            state: Inactive,
        };

        let exabgp_config = lab.generate_exabgp_config().unwrap();
        println!("generated exabgp config:\n{exabgp_config}\n\n----\n\n");
        assert_eq!(
            exabgp_config,
            "\
process announce-routes {
    run /usr/bin/env python3 /tmp/router-lab/run_exabgp.py;
    encoder json;
}

neighbor 1.255.255.250 {
    router-id 1.255.255.249;
    local-address 1.255.255.249;
    local-as 1000;
    peer-as 1000;
    family { ipv4 unicast; }
    capability { route-refresh; }
}
"
        );

        let netplan_config = lab.generate_exabgp_netplan_config().unwrap();
        println!("netplan config:\n{netplan_config}\n\n----\n\n");
        assert_eq!(
            netplan_config,
            "\
network:
  version: 2
  renderer: networkd
  ethernets:
    enp132s0f0:
      link-local: []
      dhcp4: no
      dhcp6: no
      addresses:
        - 1.255.255.253/30
        - 1.255.255.249/30:
            label: enp132s0f0:0
"
        );

        let ext_config = lab.generate_router_config(ext).unwrap();
        println!(
            "router config for {}:\n{ext_config}\n\n----\n\n",
            ext.fmt(&net),
        );
        assert_eq!(
            ext_config,
            "\
!
feature bgp
!
! Interfaces
!
interface Ethernet4/1
  no switchport
  ip address 1.192.0.1/30
  mac-address dead.006f.0401
  no shutdown
exit
!
interface Loopback0
  ip address 2.0.0.1/32
  no shutdown
exit
!
! BGP
!
route-map neighbor-in permit 65535
exit
route-map neighbor-out permit 65535
exit
!
router bgp 1000
  router-id 2.0.0.1
  neighbor 1.192.0.2 remote-as 65535
    update-source Ethernet4/1
    address-family ipv4 unicast
      next-hop-self
      route-map neighbor-in in
      route-map neighbor-out out
    exit
  exit
  address-family ipv4 unicast
    network 2.0.0.0/24
  exit
exit
!
ip route 2.0.0.0/24 null 0
!
! Create external advertisements
!
! Interface for the exabgp connection
!
interface Ethernet4/16
  no switchport
  ip address 1.255.255.250/30
  mac-address dead.006f.0410
  no shutdown
exit
!
! Route-maps for the exabgp connection
!
route-map exabgp-in permit 65535
exit
route-map exabgp-out permit 65535
exit
!
! BGP session for the exabgp connection
!
router bgp 1000
  neighbor 1.255.255.249 remote-as 1000
    update-source Ethernet4/16
    address-family ipv4 unicast
      next-hop-self
      route-map exabgp-in in
      route-map exabgp-out out
    exit
  exit
exit
"
        );

        lab.advertise_route(
            ext,
            &BgpRoute::new(ext, SimplePrefix::from(0), [1000], None, vec![1000]),
        )
        .unwrap();
        let exabgp_runner = lab.generate_exabgp_runner().unwrap();
        println!("exabgp runner:\n{exabgp_runner}\n\n----\n\n",);
        assert_eq!(
            exabgp_runner,
            "\
#!/usr/bin/env python3
import sys
import time
from os.path import expanduser as full

def wait_until(x):
    while True:
        try:
            with open(full('/tmp/router-lab/run_exabgp_control'), 'r') as f:
                t = int(f.read())
                if t >= x: return
        except FileNotFoundError:
            pass
        except ValueError:
            pass
        time.sleep(0.1)


wait_until(0)
sys.stdout.write(\"neighbor 1.255.255.250 announce route 100.0.0.0/24 next-hop self as-path [] extended-community [65535:1000]\\n\")
sys.stdout.flush()

wait_until(1_000_000)
"
        );
    }

    #[test]
    fn choose_prober_prefixes() {
        assert_eq!(
            choose_equidistant_k(20, (0..16).collect_vec()),
            (0..16).collect_vec()
        );

        assert_eq!(
            choose_equidistant_k(5, (0..16).collect_vec()),
            vec![0, 4, 8, 12, 15]
        );

        assert_eq!(
            choose_equidistant_k(3, (0..100).collect_vec()),
            vec![0, 49, 99]
        );

        assert_eq!(
            choose_equidistant_k(4, (0..100).collect_vec()),
            vec![0, 33, 66, 99]
        );

        assert_eq!(
            choose_equidistant_k(5, (0..100).collect_vec()),
            vec![0, 25, 50, 75, 99]
        );
    }
}

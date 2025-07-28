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

use std::{collections::HashMap, fs::File, io::Write, net::Ipv4Addr};

use bgpsim::{
    export::Addressor,
    formatter::NetworkFormatter,
    ospf::OspfImpl,
    types::{Prefix, RouterId},
};
use ipnet::Ipv4Net;
use itertools::Itertools;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use time::{format_description, OffsetDateTime};

use crate::{config::CONFIG, Active, RouterLab, RouterLabError};

/// Type used to (de-)serialize the `RouterLab`'s hardware mapping.
pub type HardwareMapping = HashMap<RouterId, RouterMapping>;

/// Struct used to (de-)serialize the `Analyzer`'s hardware mapping for a single router on
/// hardware.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouterMapping {
    /// Human-readable name of the router
    pub name: String,
    /// SSH name (the VDC name) of the neighbor. This is not available for external routers.
    /// Requires version `>=0.7.3`.
    #[serde(default)]
    pub ssh_name: Option<String>,
    /// Boolean indicating whether this is an internal (false) or external (true) router.
    pub is_external: bool,
    /// Internal IPv4 address assigned to this router (e.g., on its loopback interface), used for
    /// BGP's router-id.
    pub ipv4: Ipv4Addr,
    /// Internal IPv4 subnet assigned to this router (e.g., on its loopback interface), used for
    /// BGP's router-id.
    pub ipv4_net: Ipv4Net,
    /// List of interfaces this router is mapped to, to
    pub ifaces: Vec<IfaceMapping>,
    /// IPv4 address used as the src of the prober packets injected at this router.
    pub prober_src_ip: Option<Ipv4Addr>,
    /// IPv4 address used as the src of the prober packets injected at this router. Requires
    /// Requires version `>=0.7.3`.
    #[serde(default)]
    pub prober_src_mac: Option<MacAddress>,
}

impl std::fmt::Display for RouterMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "- {}: addr={}, network={}, device={}{}",
            self.name,
            self.ipv4,
            self.ipv4_net,
            self.ssh_name.clone().unwrap_or_else(|| "?".to_string()),
            self.ifaces
                .iter()
                .map(|iface| format!("\n    - {iface}"))
                .join("")
        )
    }
}

/// Struct used to (de-)serialize the `RouterLab`'s hardware mapping for a single router interface
/// on hardware.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IfaceMapping {
    /// The name of the interface. This is not available for external routers. Requires version
    /// `>=0.7.3`.
    #[serde(default)]
    pub iface_name: Option<String>,
    /// Physical address of the interface if available.
    ///
    /// Note: External routers do not have specific MAC addresses set.
    pub mac: Option<MacAddress>,
    /// IPv4 address of the interface.
    pub ipv4: Ipv4Addr,
    /// IPv4 subnet of the interface.
    pub ipv4_net: Ipv4Net,
    /// The name of the tofino interface to which this interface is connected. This is not available
    /// for external routers. Requires version `>=0.7.3`.
    #[serde(default)]
    pub tofino_iface: Option<String>,
    /// The tofino port number to which this interface is connected to. This is not available for
    /// external routers. Requires version `>=0.7.3`.
    #[serde(default)]
    pub tofino_port: Option<u8>,
    /// RouterId of the neighbor connected on this interface.
    pub neighbor: RouterId,
    /// Human-readable name of the neighbor connected on this interface.
    pub neighbor_name: String,
    /// SSH name of the neighbor. This is not available on external rotuers. Requires version
    /// `>=0.7.3`.
    #[serde(default)]
    pub neighbor_ssh_name: Option<String>,
    /// The name of the interface of the neighbor. This is not available for external routers.
    /// Requires version `>=0.7.3`.
    #[serde(default)]
    pub neighbor_iface_name: Option<String>,
    /// Physical address of the neighbor's interface connected on this interface if available.
    ///
    /// Note: External routers do not have specific MAC addresses set.
    pub neighbor_mac: Option<MacAddress>,
    /// IPv4 address of the neighbor's interface connected on this interface.
    pub neighbor_ip: Ipv4Addr,
    /// The loopback address of the neighbor
    pub neighbor_loopback_ip: Ipv4Addr,
    /// The name of the tofino interface to which the neighboring interface is connected. This is
    /// not available for external routers. Requires version `>=0.7.3`.
    #[serde(default)]
    pub neighbor_tofino_iface: Option<String>,
    /// The tofino port number to which the neighboring interface is connected to. This is not
    /// available for external routers. Requires version `>=0.7.3`.
    #[serde(default)]
    pub neighbor_tofino_port: Option<u8>,
}

impl std::fmt::Display for IfaceMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: addr={}, mac={}, target={}, network={}",
            self.iface_name
                .clone()
                .unwrap_or_else(|| CONFIG.server.exabgp_iface.clone()),
            self.ipv4,
            self.mac
                .map(|x| x.to_string())
                .unwrap_or_else(|| "xx:xx:xx:xx:xx:xx".to_string()),
            self.neighbor_name,
            self.ipv4_net,
        )
    }
}

impl<'n, P: Prefix, Q, Ospf: OspfImpl> RouterLab<'n, P, Q, Ospf, Active> {
    /// Get a reference to the hardware mapping.
    pub fn get_hardware_mapping(&self) -> &HardwareMapping {
        &self.hardware_mapping
    }

    /// Set the hardware mapping.
    pub(crate) fn compute_hardware_mapping(&mut self) -> Result<(), RouterLabError> {
        // clear the hardware mapping
        self.hardware_mapping.clear();

        // now, go through all internal routers (without the interfaces)
        for (router, (props, _)) in self.routers.iter() {
            self.hardware_mapping.insert(
                *router,
                RouterMapping {
                    name: router.fmt(self.net).to_string(),
                    ssh_name: Some(props.ssh_name.clone()),
                    is_external: false,
                    ipv4: self.addressor.router_address(*router)?,
                    ipv4_net: self.addressor.router_network(*router)?,
                    ifaces: Vec::new(),
                    prober_src_ip: self.get_prober_ifaces().get(router).map(|(_, _, x)| *x),
                    prober_src_mac: self
                        .get_prober_ifaces()
                        .get(router)
                        .map(|(_, x, _)| (*x).into()),
                },
            );
        }

        // fill in all external routers (without the interface)
        for (rid, handle) in self.external_routers.iter() {
            self.hardware_mapping.insert(
                *rid,
                RouterMapping {
                    name: rid.fmt(self.net).to_string(),
                    ssh_name: handle
                        .cisco_frr()
                        .map(|(vdc, _, _, _)| vdc.ssh_name.to_string()),
                    is_external: true,
                    ipv4: self.addressor.router_address(*rid)?,
                    ipv4_net: self.addressor.router_network(*rid)?,
                    ifaces: Vec::new(),
                    prober_src_ip: None,
                    prober_src_mac: None,
                },
            );
        }

        // finally, fill in all the links
        for ((src, src_idx), (dst, dst_idx)) in self.addressor.list_links() {
            // make sure that src is an internal router
            let ((src, src_idx), (dst, dst_idx)) = if self.routers.contains_key(&src) {
                ((src, src_idx), (dst, dst_idx))
            } else {
                ((dst, dst_idx), (src, src_idx))
            };
            let src_props = self.get_router_properties(src)?;
            let dst_props = self.get_router_properties(dst).ok();
            let src_iface = &src_props.ifaces.get(src_idx).unwrap();
            let dst_iface = &dst_props.and_then(|x| x.ifaces.get(dst_idx));

            let src_to_dst = IfaceMapping {
                iface_name: Some(src_iface.iface.clone()),
                mac: Some(src_iface.mac.into()),
                ipv4: self.addressor.iface_address(src, dst)?,
                ipv4_net: self.addressor.iface_network(src, dst)?,
                tofino_iface: Some(src_iface.tofino_iface.clone()),
                tofino_port: Some(src_iface.tofino_port),
                neighbor: dst,
                neighbor_name: dst.fmt(self.net).to_string(),
                neighbor_ssh_name: dst_props.map(|x| x.ssh_name.clone()),
                neighbor_iface_name: dst_iface.map(|x| x.iface.clone()),
                neighbor_mac: dst_iface.map(|x| x.mac.into()),
                neighbor_ip: self.addressor.iface_address(dst, src)?,
                neighbor_loopback_ip: self.addressor.router_address(dst)?,
                neighbor_tofino_iface: dst_iface.map(|x| x.tofino_iface.clone()),
                neighbor_tofino_port: dst_iface.map(|x| x.tofino_port),
            };

            let dst_to_src = IfaceMapping {
                iface_name: dst_iface.map(|x| x.iface.clone()),
                mac: dst_iface.map(|x| x.mac.into()),
                ipv4: self.addressor.iface_address(dst, src)?,
                ipv4_net: self.addressor.iface_network(dst, src)?,
                tofino_iface: dst_iface.map(|x| x.tofino_iface.clone()),
                tofino_port: dst_iface.map(|x| x.tofino_port),
                neighbor: src,
                neighbor_name: src.fmt(self.net).to_string(),
                neighbor_ssh_name: Some(src_props.ssh_name.clone()),
                neighbor_iface_name: Some(src_iface.iface.clone()),
                neighbor_mac: Some(src_iface.mac.into()),
                neighbor_ip: self.addressor.iface_address(src, dst)?,
                neighbor_loopback_ip: self.addressor.router_address(src)?,
                neighbor_tofino_iface: Some(src_iface.tofino_iface.clone()),
                neighbor_tofino_port: Some(src_iface.tofino_port),
            };

            self.hardware_mapping
                .get_mut(&src)
                .unwrap()
                .ifaces
                .push(src_to_dst);
            self.hardware_mapping
                .get_mut(&dst)
                .unwrap()
                .ifaces
                .push(dst_to_src);
        }

        // Create a log message with the hardware mapping:
        log::info!(
            "[RouterLab] Hardware Mapping:\n{}",
            self.hardware_mapping
                .values()
                .map(|m| format!("{m}"))
                .join("\n")
        );

        // store the file to disk
        let mut hwmap_path = std::env::temp_dir();

        let cur_time = OffsetDateTime::now_local()
            .unwrap_or_else(|_| OffsetDateTime::now_utc())
            .format(
                &format_description::parse("[year]-[month]-[day]_[hour]-[minute]-[second]")
                    .unwrap(),
            )
            .unwrap();

        hwmap_path.push(format!("router_lab_hardware_mapping_{cur_time}.json"));
        let hwmap_content = serde_json::to_string_pretty(&self.hardware_mapping).unwrap();
        let mut hwmap_file = File::create(&hwmap_path)?;
        hwmap_file.write_all(hwmap_content.as_bytes())?;
        log::debug!(
            "[RouterLab] Stored hardware mapping to {}",
            hwmap_path.to_string_lossy()
        );

        Ok(())
    }
}

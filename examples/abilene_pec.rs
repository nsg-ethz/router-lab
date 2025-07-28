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

use std::{net::Ipv4Addr, time::Duration};

use bgpsim::{
    builder::*,
    prelude::{BasicEventQueue, GlobalOspf, Network},
    topology_zoo::TopologyZoo,
    types::SimplePrefix as P,
};
use ipnet::Ipv4Net;
use router_lab::{RouterLab, RouterLabError};
use tokio::time::timeout;

mod utils;

#[tokio::main]
async fn main() -> Result<(), RouterLabError> {
    pretty_env_logger::init();

    // create the network
    let topo = TopologyZoo::Abilene;
    let mut net: Network<P, BasicEventQueue<P>, GlobalOspf> =
        topo.build(BasicEventQueue::<P>::new());
    let p = P::from(0);
    let se = net.get_router_id("Seattle")?;
    let ny = net.get_router_id("NewYork")?;
    let la = net.get_router_id("LosAngeles")?;
    let sn = net.get_router_id("Sunnyvale")?;
    let ka = net.get_router_id("KansasCity")?;
    let at = net.get_router_id("Atlanta")?;
    net.build_external_routers(|_, _| vec![se, ny, la], ())?;
    let e_se = net.get_router_id("Seattle_ext_11")?;
    let e_ny = net.get_router_id("NewYork_ext_12")?;
    let e_la = net.get_router_id("LosAngeles_ext_13")?;
    net.build_link_weights(uniform_integer_link_weight, (10, 100))?;
    net.build_ibgp_route_reflection(|_, _| vec![sn, ka, at], ())?;
    net.build_ebgp_sessions()?;
    net.build_advertisements(p, |_, _| vec![vec![e_ny], vec![e_se, e_la]], 3)?;

    // create the lab
    let mut lab = RouterLab::new(&net)?;

    // prepare the prefix equivalence class.
    lab.register_pec(
        p,
        (0..256)
            .map(|x| Ipv4Addr::from((200u32 << 24) + (x << 8)))
            .map(|ip| Ipv4Net::new(ip, 24).unwrap())
            .collect(),
    );

    // set all link delays to 10ms
    lab.set_link_delays_from_geolocation(topo.geo_location());

    // write configuration to a file for debugging
    utils::write_config(&mut lab)?;

    // connect the network
    let mut lab = lab.connect().await?;
    lab.wait_for_convergence().await?;

    // start the capture
    let mut capture = lab.start_capture(1, 1_000, false).await?;

    // wait for ctrl-c
    let mut pos = 0;
    println!("Network is running! Press Ctrl-C to exit!");
    loop {
        match timeout(Duration::from_millis(100), tokio::signal::ctrl_c()).await {
            Ok(_) => break,
            Err(_) => {
                let new_pos = capture.get_samples().await?.len();
                let new_samples = new_pos - pos;
                pos = new_pos;
                println!("Num samples: {new_samples}")
            }
        }
    }
    println!();

    let result = lab.stop_capture(capture).await?;
    println!(
        "Num samples: {}",
        result.values().map(|x| x.len()).sum::<usize>()
    );

    // disconnect the network.
    let _ = lab.disconnect().await?;

    // wait for one second
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}

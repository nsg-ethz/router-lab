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

use std::time::Duration;

use bgpsim::prelude::*;
use router_lab::{export_capture_to_csv, RouterLab, RouterLabError};

#[tokio::main]
async fn main() -> Result<(), RouterLabError> {
    pretty_env_logger::init();

    let (net, (r1, r2)) = net! {
        Prefix = SinglePrefix;
        links = {
            r1 -> r2: 10;
            r1 -> r3: 100;
            r2 -> r3: 100;
        };
        sessions = {
            r1 -> r2;
            r1 -> r3;
            r2 -> r3;
            e1!(100) -> r1;
            e2!(200) -> r2;
        };
        routes = {
            e1 -> SinglePrefix as {path: [100, 100, 100, 100, 1000]};
            e2 -> SinglePrefix as {path: [200, 200, 1000]};
        };
        return (r1, r2);
    };

    // create the lab
    let lab = RouterLab::new(&net)?;

    // connect the network
    let mut lab = lab.connect().await?;
    lab.wait_for_convergence().await?;

    // start the capture
    let capture_frequency = 5_000;
    let handle = lab.start_capture(1, capture_frequency, false).await?;

    tokio::time::sleep(Duration::from_secs(5)).await;
    lab.disable_link(r1, r2).await?;
    tokio::time::sleep(Duration::from_secs(5)).await;

    let capture = lab.stop_capture(handle).await?;
    let _ = export_capture_to_csv(&net, &capture, "example_data", "link_failure")?;

    // disconnect the network.
    let _ = lab.disconnect().await?;

    Ok(())
}

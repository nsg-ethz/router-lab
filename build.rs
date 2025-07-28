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

use std::{
    env::current_dir,
    fs::{copy, create_dir, read_dir},
    path::PathBuf,
};

// Example custom build script.
fn main() {
    {
        // Tell Cargo that if the given file changes, to rerun this build script.
        println!("cargo:rerun-if-changed=src/test/config");

        // copy all files in that folder into the build folder.
        let mut dst = PathBuf::from(format!("{}/.config", std::env::var("OUT_DIR").unwrap()));
        let mut src = current_dir().unwrap();
        src.push("src");
        src.push("test");
        src.push("config");

        // make the out directory
        if !dst.exists() {
            create_dir(&dst).unwrap();
        }

        for entry in read_dir(src.clone()).unwrap() {
            let filename = entry.unwrap().file_name();
            src.push(&filename);
            dst.push(&filename);
            copy(&src, &dst).unwrap();
            src.pop();
            dst.pop();
        }
    }
}

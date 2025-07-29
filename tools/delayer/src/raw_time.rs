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

use libc::timeval;

const US_PER_SEC: i64 = 1_000_000;

#[inline(always)]
pub fn usec_to_tv(usec: i64) -> timeval {
    timeval {
        tv_sec: usec / US_PER_SEC,
        tv_usec: usec % US_PER_SEC,
    }
}

#[inline(always)]
pub fn tv_add(a: timeval, b: timeval) -> timeval {
    let mut tv = timeval {
        tv_sec: a.tv_sec + b.tv_sec,
        tv_usec: a.tv_usec + b.tv_usec,
    };

    if tv.tv_usec >= US_PER_SEC {
        tv.tv_sec += 1;
        tv.tv_usec -= US_PER_SEC;
    }

    tv
}

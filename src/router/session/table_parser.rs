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

//! Module for parsing cisco tables.

use itertools::Itertools;
use thiserror::Error;

pub struct Assert<const N: usize>;
impl<const N: usize> Assert<N> {
    pub const NON_ZERO: usize = N - 1;
}

/// Parse a table using the given header field names. The first line must be the table header. It
/// returns a vector for each non-empty line, containing a tuple of flags (the thing before the
/// first column), and a vector containing all other elements.
pub fn parse_table<'a, const N: usize>(
    table: &'a str,
    headers: [&'static str; N],
) -> Result<Vec<(&'a str, [&'a str; N])>, TableParseError> {
    _ = Assert::<N>::NON_ZERO;

    let mut lines = table.lines();
    let header = lines
        .next()
        .ok_or_else(|| TableParseError::InvalidHeader(String::new()))?;

    if header.split_whitespace().join(" ") != headers.iter().join(" ") {
        return Err(TableParseError::InvalidHeader(header.to_string()));
    }

    let positions = headers.map(|h| header.find(h).unwrap());
    let mut idx = 0;
    let ranges = headers.map(|_| {
        let range = if idx + 1 == N {
            (positions[idx], None)
        } else {
            (positions[idx], Some(positions[idx + 1]))
        };
        idx += 1;
        range
    });

    let mut results = Vec::new();
    for row in lines {
        if row.is_empty() {
            continue;
        }
        let flags = &row[..positions[0]];

        let cells = ranges.map(|r| {
            match r {
                (low, Some(high)) => &row[low..high],
                (low, None) => &row[low..],
            }
            .trim()
        });
        results.push((flags, cells))
    }

    Ok(results)
}

/// Parse a table using the given header field names. The first line must be the table header. It
/// returns a vector for each non-empty line, containing all elements separately.
///
/// This function assumes (and checks!) that no field is empty.
pub fn parse_table_non_empty<'a, const N: usize>(
    table: &'a str,
    headers: [&'static str; N],
) -> Result<Vec<[&'a str; N]>, TableParseError> {
    // make sure that N is at least 1.
    _ = Assert::<N>::NON_ZERO;

    let mut lines = table.lines();
    let header = lines
        .next()
        .ok_or_else(|| TableParseError::InvalidHeader(String::new()))?;

    if header.split_whitespace().join(" ") != headers.iter().join(" ") {
        return Err(TableParseError::InvalidHeader(header.to_string()));
    }

    let mut results = Vec::new();
    for row in lines {
        if row.is_empty() {
            continue;
        }
        let cells = row.split_whitespace().collect::<Vec<_>>();
        if headers.len() != cells.len() {
            return Err(TableParseError::RowParseError(row.to_string()));
        }
        results.push(cells.try_into().unwrap())
    }

    Ok(results)
}

/// Error while parsing a Cisco table
#[derive(Debug, Error)]
pub enum TableParseError {
    /// Invalid header line.
    #[error("Invalid header line: {0}")]
    InvalidHeader(String),
    /// Route row is too short
    #[error("A row is too short to be parsed: {0}")]
    RowTooShort(String),
    /// Error parsing a table row
    #[error("A row could not be parsed: {0}")]
    RowParseError(String),
}

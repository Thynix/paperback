/*
 * paperback: paper backup generator suitable for long-term storage
 * Copyright (C) 2018-2022 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use paperback_core::v0::{FromWire, MainDocument};

// `MainDocument::from_wire` is the boundary a main document QR/text scan
// crosses before any ed25519 signature verification happens. Decoding
// arbitrary bytes must never panic -- returning `Ok` or `Err` are both
// acceptable outcomes.
fuzz_target!(|data: &[u8]| {
    let _ = MainDocument::from_wire(data);
});

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
use paperback_core::v0::{
    pdf::qr::{Joiner, Part},
    FromWire,
};

// A scanned QR code is decoded as a `Part` and fed into a `Joiner`, all
// before any checksum or signature verification takes place -- this is the
// earliest point at which a scuffed or adversarial QR code reaches the
// library. Decoding and joining arbitrary bytes must never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(part) = Part::from_wire(data) {
        let mut joiner = Joiner::new();
        let _ = joiner.add_part(part);
    }
});

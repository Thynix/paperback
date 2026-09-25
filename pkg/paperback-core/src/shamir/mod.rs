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

//! This package implements a Shamir Secret Sharing scheme in GF(2^32), meaning
//! that the data is split up into 4-byte chunks (and all x and y values are
//! 32-bit integers).
//!
//! ## Security ##
//! **This implementation is not remotely constant time and has not been
//! reviewed by any cryptographers. This was implemented by me from scratch
//! because there was no alternative crate implementing the necessary
//! algorithms. Of the few SSS crates I found, all had security bugs and none
//! provided for 32-bit x-values which is a requirement of paperback's design.**

mod dealer;
mod gf;
pub(crate) mod shard;

pub use dealer::Dealer;
pub use shard::Shard;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("lagrange interpolation failed: {0}")]
    LagrangeError(#[from] gf::Error),

    #[error("threshold must be at least 1 (got 0)")]
    ZeroThreshold,

    #[error("must be provided at least one shard")]
    NoShards,

    #[error("shards have inconsistent threshold: expected {expected} but shard had {actual}")]
    InconsistentThreshold { expected: u32, actual: u32 },

    #[error(
        "shards have inconsistent length: expected {expected} y-values but shard had {actual}"
    )]
    InconsistentShardLength { expected: usize, actual: usize },

    #[error("shards have inconsistent secret length: expected {expected} but shard had {actual}")]
    InconsistentSecretLen { expected: usize, actual: usize },

    #[error("wrong number of shards: need exactly {needed} but got {given}")]
    WrongShardCount { needed: usize, given: usize },

    #[error("shard secret_len ({secret_len}) exceeds available secret bytes ({available})")]
    SecretLenOutOfRange { secret_len: usize, available: usize },
}

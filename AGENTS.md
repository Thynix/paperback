# AGENTS.md

Guidance for AI agents working in this repository.

## What this project is

`paperback` generates encrypted paper backups. A secret is encrypted under a
document key, that key is split with Shamir Secret Sharing into `k` key shards
held by different people, and everything is rendered to PDFs that get printed
and laminated. Any `n` of the `k` shard holders can recover the secret without
the original author present — the tool is explicitly designed to work as a
digital will.

Two consequences shape almost every rule below:

1. **The output is paper, and it is read back decades later.** Input arrives
   from a QR scan of a scuffed, faded page, or from a human typing z-base-32 by
   hand. Malformed, truncated, and corrupted input is the normal case, not the
   exceptional one.
2. **The threat model is adversarial.** `DESIGN.md` assumes up to `n-1`
   malicious shard holders who may supply forged shards. Code that handles
   shards is handling attacker-controlled bytes.

`DESIGN.md` is the specification and takes precedence over any code comment.
Read the relevant section before changing anything cryptographic. If the code
and `DESIGN.md` disagree, one of them is wrong — say so and get a decision.
Do not silently pick a side.

## Build, test, lint

```
cargo build                       # debug
cargo build --release             # release (lto = true, slow)
cargo test --workspace            # 103 tests, ~40s after compilation
cargo test --workspace --release  # CI runs this too; some bounds differ by profile
cargo clippy --workspace --all-targets --all-features
cargo fmt --all -- --check        # default rustfmt, no config file
cargo bench --workspace           # criterion
```

Known build friction, in order of how much time it wastes:

- **The first build needs network access for a git dependency.**
  `unsigned-varint` is pinned to a branch of a personal fork, not to crates.io.
  In a restricted sandbox this fails with `Read-only file system (os error 30)`
  writing to `~/.cargo/git/db`, or `CONNECT tunnel failed, response 403` if a
  proxy blocks git-over-HTTPS. Neither message mentions the real cause. Run the
  fetch unsandboxed, or point `CARGO_HOME` somewhere writable with network
  reachable.
- **`warning: patch for the non root package will be ignored` on every build is
  expected.** `[patch.crates-io]` is duplicated in `pkg/paperback-core/Cargo.toml`
  where cargo ignores it. Harmless; do not "fix" it by moving the working root
  stanza. It is a known cleanup.
- A `rustybuzz v0.4.0` future-incompatibility warning comes from a transitive
  dependency of `printpdf`. Not actionable here.

## Layout

| Path | Contents |
|:-----|:---------|
| `src/main.rs` | CLI: `backup`, `recover`, `expand-shards`, `recreate-shards`, `reprint` |
| `src/raw.rs` | `raw` subcommands — text in/out instead of PDFs, for scripting |
| `pkg/paperback-core/src/shamir/` | Shamir Secret Sharing over GF(2^32); `gf.rs` is the field arithmetic |
| `pkg/paperback-core/src/v0/` | The v0 schema: `backup.rs`, `recover.rs`, `mod.rs` |
| `pkg/paperback-core/src/v0/wire/` | nom parsers and serializers — the untrusted-input boundary |
| `pkg/paperback-core/src/v0/pdf/` | PDF and QR rendering; `qr.rs` also parses scanned payloads |
| `DESIGN.md` | The specification and threat model |

## Hard rules

**Never panic on untrusted input.** This is the single most important rule and
the one this codebase has most often broken. Anything reaching the code from a
document, a key shard, a QR scan, typed codewords, or a CLI argument must
produce a `Result`, never a panic. In practice that means no `assert!`,
`unwrap()`, `expect()`, `copy_from_slice`, bare slice indexing, `Vec::drain`, or
unchecked arithmetic on such values. A panic during a recovery ceremony is a
failure of the tool's entire purpose — the shard holders are assembled, and the
process aborts with a Rust backtrace. Use `checked_add`, `try_into`, and
explicit length checks.

**The v0 wire format is a stored format.** Backups already exist on paper.
Changing the bytes, the field order, the signed or hashed input, or the QR
chunking makes printed documents unreadable. Any incompatible change requires a
new version module alongside `v0`, not an edit to it. Say plainly in your
summary when a change touches serialization.

**Library code must not print.** `pkg/paperback-core` must not write to stdout
or stderr. Deciding what a user sees is the CLI's job, and a library that prints
the encrypted payload defeats a paper-only backup tool.

**Keep `#![forbid(unsafe_code)]`** in `pkg/paperback-core/src/lib.rs`.

**Do not implement cryptographic primitives.** Use the existing crates —
`chacha20poly1305`, `ed25519-dalek`, `multihash`. The one hand-rolled component
is the GF(2^32) field arithmetic in `shamir/gf.rs`, whose characteristic
polynomial and constant-time properties have been checked; do not rewrite it
casually. Note that `shamir/mod.rs` itself states the implementation is not
constant time and has not been reviewed by cryptographers.

**A cryptographic change updates `DESIGN.md` in the same change.** The two have
already drifted in several places; do not widen the gap.

## Conventions

- **Every `.rs` file starts with the GPL-3.0-or-later header.** All 19 source
  files carry it. Copy it verbatim from an existing file for anything new.
- **Formatting is default `rustfmt`** — there is no config file. `Cargo.toml`
  uses tabs; the workflow YAML uses spaces.
- **Commit subjects are `area: lowercase description`.** Observed areas:
  `shamir`, `pdf`, `wire`, `gf`, `cli`, `main`, `raw`, `recover`, `expand`,
  `cargo`, `gha`, `ci`, `tests`, `paperback-core`, `pkg`. Use `*:` for
  tree-wide changes. Example: `wire: reject over-long multihash lengths`.
- **Upstream commits carry `Signed-off-by:` (DCO).** It is not documented in
  the tree, but the maintainer signs off on every commit; match it for anything
  intended upstream.
- Version is `0.0.0` in both crates and there is no MSRV (`rust-version`)
  declared. CI installs `stable` only.

## Testing

Tests live in `#[cfg(test)]` modules in the file they cover, and lean heavily on
`quickcheck` property tests. The established pattern is a round-trip property:
encode, decode, assert equality.

That pattern has a gap you should actively close: **every existing test feeds
structurally valid data** generated by `Arbitrary`. There is no fuzzing and no
test anywhere that feeds truncated or corrupted bytes to a parser and asserts
`Err`-not-panic. When you touch a parser or anything handling shard, document,
QR, or codeword input, add a malformed-input test. `pdf/generate.rs`,
`v0/recover.rs`, and `src/raw.rs` currently have no tests of their own.

Run `cargo test --workspace --release` as well as the debug run before claiming
a change is good — some test bounds are `cfg`-gated smaller in debug builds, so
the release run exercises different sizes.

## Before you claim something works

Build success is not evidence. `cargo test`, `clippy`, and `fmt` all pass on
code containing crashes reachable from ordinary input, so a green run proves
little about this project's actual failure modes. For a behavioural change,
run the binary:

```
paperback backup -n 2 -k 3 secret.txt
```

and, where the change touches recovery or parsing, feed it deliberately broken
input and confirm it produces an error rather than a panic.

## Known issues

If a `plans/` directory is present, it holds per-finding remediation plans from
a code review, indexed in `plans/README.md`. Check it before investigating a
suspected bug — it may already be written up with a proposed fix. It is a local
review artifact and is not part of upstream.

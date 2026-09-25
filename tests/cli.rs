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

//! CLI-level tests that exercise the compiled `paperback` binary as a
//! subprocess, so they can assert on what actually reaches stdout and
//! stderr. These specifically cover the encrypted main document payload no
//! longer being printed to stdout unless explicitly requested with
//! `--print-data`.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

fn unique_temp_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "paperback-cli-test-{}-{}-{}-{}",
        name,
        std::process::id(),
        nanos,
        count
    ));
    fs::create_dir_all(&dir).expect("failed to create temp dir for CLI test");
    dir
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_paperback"))
}

fn run(dir: &Path, args: &[&str], stdin_data: Option<&str>) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn paperback binary");

    if let Some(data) = stdin_data {
        child
            .stdin
            .take()
            .expect("child stdin was not piped")
            .write_all(data.as_bytes())
            .expect("failed to write test stdin data");
    } else {
        drop(child.stdin.take());
    }

    child
        .wait_with_output()
        .expect("failed to wait for paperback binary")
}

/// A crude but sufficient check for the kind of long, digit-only line that
/// the Base10-multibase-encoded main document QR payload produces. Ordinary
/// CLI chatter (document IDs, checksums, prompts) is never a long run of
/// nothing but decimal digits.
fn contains_long_digit_line(text: &str) -> bool {
    text.lines()
        .any(|line| line.len() > 50 && line.chars().all(|c| c.is_ascii_digit()))
}

#[test]
fn backup_without_print_data_flag_produces_no_extra_stdout() {
    let dir = unique_temp_dir("backup-no-print-data");
    fs::write(dir.join("secret.txt"), b"a small secret").unwrap();

    let output = run(&dir, &["backup", "-n", "2", "-k", "2", "secret.txt"], None);
    assert!(output.status.success(), "backup failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Main Document:"));
    assert!(
        !contains_long_digit_line(&stdout),
        "unexpected long digit-only line in stdout without --print-data: {}",
        stdout
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn backup_with_print_data_flag_prints_payload() {
    let dir = unique_temp_dir("backup-with-print-data");
    fs::write(dir.join("secret.txt"), b"a small secret").unwrap();

    let output = run(
        &dir,
        &["backup", "-n", "2", "-k", "2", "--print-data", "secret.txt"],
        None,
    );
    assert!(output.status.success(), "backup failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        contains_long_digit_line(&stdout),
        "expected the main document payload in stdout with --print-data: {}",
        stdout
    );
    assert!(stderr.contains("WARNING"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reprint_print_data_flag_smoke() {
    let dir = unique_temp_dir("reprint-print-data");
    fs::write(dir.join("secret.txt"), b"a small secret").unwrap();

    let backup_output = run(
        &dir,
        &["backup", "-n", "2", "-k", "2", "--print-data", "secret.txt"],
        None,
    );
    assert!(
        backup_output.status.success(),
        "backup failed: {:?}",
        backup_output
    );
    let payload = String::from_utf8_lossy(&backup_output.stdout).to_string();
    assert!(!payload.trim().is_empty());

    // `read_multiline()` reads lines until a blank line, once per QR part;
    // reproduce exactly that shape, one payload line followed by a blank
    // line, repeated for however many parts the payload has.
    let stdin_data = payload
        .lines()
        .map(|line| format!("{}\n\n", line))
        .collect::<String>();

    // Without --print-data: reprint must not echo the payload back.
    let without_flag = run(
        &dir,
        &["reprint", "--interactive", "--main-document"],
        Some(&stdin_data),
    );
    assert!(
        without_flag.status.success(),
        "reprint failed: {:?}",
        without_flag
    );
    let stdout = String::from_utf8_lossy(&without_flag.stdout);
    assert!(!contains_long_digit_line(&stdout));

    // With --print-data: reprint must print the payload and warn on stderr.
    let with_flag = run(
        &dir,
        &[
            "reprint",
            "--interactive",
            "--main-document",
            "--print-data",
        ],
        Some(&stdin_data),
    );
    assert!(
        with_flag.status.success(),
        "reprint failed: {:?}",
        with_flag
    );
    let stdout = String::from_utf8_lossy(&with_flag.stdout);
    let stderr = String::from_utf8_lossy(&with_flag.stderr);
    assert!(contains_long_digit_line(&stdout));
    assert!(stderr.contains("WARNING"));

    let _ = fs::remove_dir_all(&dir);
}

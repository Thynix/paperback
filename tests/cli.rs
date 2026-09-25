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
    // --force is needed here because this reprints the same main document a
    // second time into the same directory, which would otherwise collide
    // with the PDF the first reprint call above just wrote.
    let with_flag = run(
        &dir,
        &[
            "reprint",
            "--interactive",
            "--main-document",
            "--print-data",
            "--force",
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

/// `recover --interactive` reads a main document (via the QR-part joiner
/// protocol), then, per required shard, a plain multibase payload and a line
/// of codewords -- terminating each multiline prompt on a blank line. This
/// builds exactly that shape of piped input directly from the
/// `paperback_core` library (rather than through another CLI invocation,
/// since there is no CLI flag that prints a shard's own text form) and feeds
/// it to the compiled binary over a pipe (i.e. non-TTY stdin), asserting
/// that recovery still succeeds end-to-end now that interactive prompts
/// suppress terminal echo by default -- piped input must be unaffected by
/// that change.
#[test]
fn recover_interactive_accepts_piped_input_end_to_end() {
    use paperback_core::latest::{self as paperback, ToWire};

    let secret = b"a small secret for the recover CLI test".to_vec();
    let backup = paperback::Backup::new(1, &secret).expect("create backup");
    let main_document = backup.main_document().clone();
    let shard = backup.next_shard().expect("create shard");
    let (encrypted_shard, codewords) = shard.encrypt().expect("encrypt shard");

    let main_document_lines = main_document
        .debug_qr_data_strings()
        .expect("main document qr strings");
    let shard_multibase = encrypted_shard.to_wire_multibase(multibase::Base::Base32Z);
    let codewords_line = codewords.join(" ");

    let mut stdin_data = String::new();
    for line in &main_document_lines {
        stdin_data.push_str(line);
        stdin_data.push_str("\n\n");
    }
    stdin_data.push_str(&shard_multibase);
    stdin_data.push_str("\n\n");
    stdin_data.push_str(&codewords_line);
    stdin_data.push_str("\n\n");

    let dir = unique_temp_dir("recover-piped");
    let output_path = dir.join("recovered.bin");
    let output = run(
        &dir,
        &[
            "recover",
            "--interactive",
            output_path.to_str().expect("output path is valid UTF-8"),
        ],
        Some(&stdin_data),
    );
    assert!(output.status.success(), "recover failed: {:?}", output);

    let recovered = fs::read(&output_path).expect("read recovered secret");
    assert_eq!(recovered, secret);

    let _ = fs::remove_dir_all(&dir);
}

/// The `--echo`/`--no-echo` flags added alongside terminal-echo suppression
/// must be mutually exclusive at the CLI level (clap should reject both
/// together before any interactive prompt is attempted).
#[test]
fn recover_rejects_echo_and_no_echo_together() {
    let dir = unique_temp_dir("recover-echo-conflict");

    let output = run(
        &dir,
        &["recover", "--interactive", "--echo", "--no-echo", "-"],
        None,
    );
    assert!(
        !output.status.success(),
        "recover should reject --echo and --no-echo together: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected a clap argument-conflict message, got: {}",
        stderr
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Builds the same recover-interactive stdin shape used by
/// `recover_interactive_accepts_piped_input_end_to_end`, for the --force /
/// output-clobber tests below.
fn build_recover_stdin(
    main_document: &paperback_core::latest::MainDocument,
    encrypted_shard: &paperback_core::latest::EncryptedKeyShard,
    codewords: &paperback_core::latest::KeyShardCodewords,
) -> String {
    use paperback_core::latest::ToWire;

    let main_document_lines = main_document
        .debug_qr_data_strings()
        .expect("main document qr strings");
    let shard_multibase = encrypted_shard.to_wire_multibase(multibase::Base::Base32Z);
    let codewords_line = codewords.join(" ");

    let mut stdin_data = String::new();
    for line in &main_document_lines {
        stdin_data.push_str(line);
        stdin_data.push_str("\n\n");
    }
    stdin_data.push_str(&shard_multibase);
    stdin_data.push_str("\n\n");
    stdin_data.push_str(&codewords_line);
    stdin_data.push_str("\n\n");
    stdin_data
}

/// `recover --interactive OUTPUT` must refuse to silently truncate an
/// existing file at OUTPUT unless --force is given -- the pre-existing
/// file's contents must be left untouched.
#[test]
fn recover_refuses_to_clobber_output_by_default() {
    use paperback_core::latest as paperback;

    let secret = b"a small secret for the no-clobber test".to_vec();
    let backup = paperback::Backup::new(1, &secret).expect("create backup");
    let main_document = backup.main_document().clone();
    let shard = backup.next_shard().expect("create shard");
    let (encrypted_shard, codewords) = shard.encrypt().expect("encrypt shard");
    let stdin_data = build_recover_stdin(&main_document, &encrypted_shard, &codewords);

    let dir = unique_temp_dir("recover-no-clobber");
    let output_path = dir.join("existing.bin");
    fs::write(&output_path, b"pre-existing content").expect("write pre-existing output file");

    let output = run(
        &dir,
        &[
            "recover",
            "--interactive",
            output_path.to_str().expect("output path is valid UTF-8"),
        ],
        Some(&stdin_data),
    );
    assert!(
        !output.status.success(),
        "recover should refuse to overwrite an existing output file: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists") && stderr.contains("--force"),
        "expected an already-exists/--force error, got: {}",
        stderr
    );

    let contents = fs::read(&output_path).expect("read output file");
    assert_eq!(contents, b"pre-existing content");

    let _ = fs::remove_dir_all(&dir);
}

/// Same setup as above, but with --force: the pre-existing file must be
/// overwritten with the recovered secret, and (on Unix) end up restricted to
/// mode 0600 even though it pre-existed with default-umask permissions --
/// exercising the case where `--force` truncates an existing inode in place
/// rather than creating a fresh one, where `OpenOptions::mode()` alone would
/// not apply.
#[test]
fn recover_force_flag_overwrites() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use paperback_core::latest as paperback;

    let secret = b"a small secret for the force-overwrite test".to_vec();
    let backup = paperback::Backup::new(1, &secret).expect("create backup");
    let main_document = backup.main_document().clone();
    let shard = backup.next_shard().expect("create shard");
    let (encrypted_shard, codewords) = shard.encrypt().expect("encrypt shard");
    let stdin_data = build_recover_stdin(&main_document, &encrypted_shard, &codewords);

    let dir = unique_temp_dir("recover-force-overwrite");
    let output_path = dir.join("existing.bin");
    fs::write(&output_path, b"pre-existing content").expect("write pre-existing output file");

    let output = run(
        &dir,
        &[
            "recover",
            "--interactive",
            "--force",
            output_path.to_str().expect("output path is valid UTF-8"),
        ],
        Some(&stdin_data),
    );
    assert!(
        output.status.success(),
        "recover --force should overwrite an existing output file: {:?}",
        output
    );

    let contents = fs::read(&output_path).expect("read output file");
    assert_eq!(contents, secret);

    #[cfg(unix)]
    {
        let mode = fs::metadata(&output_path)
            .expect("stat output file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "expected mode 0600, got {:o}", mode);
    }

    let _ = fs::remove_dir_all(&dir);
}

/// `raw restore`'s output file is a recovered plaintext secret, so it must
/// be created with mode 0600 rather than inheriting the process umask.
#[cfg(unix)]
#[test]
fn raw_restore_output_has_0600_permissions() {
    use paperback_core::latest::{self as paperback, ToWire};
    use std::os::unix::fs::PermissionsExt;

    let secret = b"a small secret for the raw restore permissions test".to_vec();
    let backup = paperback::Backup::new(1, &secret).expect("create backup");
    let main_document = backup.main_document().clone();
    let shard = backup.next_shard().expect("create shard");
    let (encrypted_shard, codewords) = shard.encrypt().expect("encrypt shard");

    let dir = unique_temp_dir("raw-restore-perms");
    let main_document_path = dir.join("main_document.txt");
    let shard_path = dir.join("shard.txt");
    fs::write(
        &main_document_path,
        main_document.to_wire_multibase(multibase::Base::Base32Z),
    )
    .expect("write main document file");
    fs::write(
        &shard_path,
        encrypted_shard.to_wire_multibase(multibase::Base::Base32Z),
    )
    .expect("write shard file");

    let output_path = dir.join("recovered.bin");
    let codewords_line = format!("{}\n", codewords.join(" "));

    let output = run(
        &dir,
        &[
            "raw",
            "restore",
            "-M",
            main_document_path.to_str().expect("path is valid UTF-8"),
            "-s",
            shard_path.to_str().expect("path is valid UTF-8"),
            output_path.to_str().expect("path is valid UTF-8"),
        ],
        Some(&codewords_line),
    );
    assert!(output.status.success(), "raw restore failed: {:?}", output);

    let mode = fs::metadata(&output_path)
        .expect("stat output file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "expected mode 0600, got {:o}", mode);

    let _ = fs::remove_dir_all(&dir);
}

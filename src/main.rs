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

mod raw;

use std::{
    error::Error as StdError,
    fs::File,
    io,
    io::{prelude::*, BufReader, BufWriter, IsTerminal},
};

use anyhow::{anyhow, bail, ensure, Context, Error};
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};

extern crate paperback_core;
use paperback_core::latest as paperback;

use paperback::{
    pdf::qr, wire, Backup, EncryptedKeyShard, FromWire, KeyShard, KeyShardCodewords, MainDocument,
    NewShardKind, ToPdf, UntrustedQuorum,
};

// paperback-cli backup [--sealed] -n <QUORUM SIZE> -k <SHARDS> INPUT
fn backup_cli() -> Command {
    Command::new("backup")
            .about(r#"Create a paperback backup."#)
            .arg(Arg::new("sealed")
                .long("sealed")
                .help("Create a sealed backup, which cannot be expanded (have new shards be created) after creation.")
                .action(ArgAction::SetTrue))
            .arg(Arg::new("quorum-size")
                .short('n')
                .long("quorum-size")
                .value_name("QUORUM SIZE")
                .help("Number of shards required to recover the document (must not be larger than --shards).")
                .action(ArgAction::Set)
                .required(true))
            .arg(Arg::new("shards")
                .short('k')
                .long("shards")
                .value_name("NUM SHARDS")
                .help("Number of shards to create (must not be smaller than --quorum-size).")
                .action(ArgAction::Set)
                .required(true))
            .arg(Arg::new("print-data")
                .long("print-data")
                .help("Print the encrypted main document QR payload to stdout. This is sensitive data -- only use this until PDF scanning is implemented and you need the text form back without a scanner.")
                .action(ArgAction::SetTrue))
            .arg(Arg::new("INPUT")
                .help(r#"Path to file containing secret data to backup ("-" to read from stdin)."#)
                .action(ArgAction::Set)
                .allow_hyphen_values(true)
                .required(true)
                .index(1))
}

/// Validates that `quorum_size` (`-n`) and `num_shards` (`-k`) describe a
/// backup that can actually be recovered: the quorum size must be at least
/// one, and there must be at least as many shards created as are needed to
/// meet the quorum.
pub(crate) fn validate_shard_counts(quorum_size: u32, num_shards: u32) -> Result<(), Error> {
    ensure!(
        quorum_size > 0,
        "invalid arguments: --quorum-size must be at least 1 (a backup with quorum size 0 cannot meaningfully be recovered)"
    );
    ensure!(
        num_shards >= quorum_size,
        "invalid arguments: number of shards ({}) cannot be smaller than quorum size ({}) -- such a backup is unrecoverable",
        num_shards,
        quorum_size
    );
    Ok(())
}

fn backup(matches: &ArgMatches) -> Result<(), Error> {
    let sealed = matches.get_flag("sealed");
    let quorum_size: u32 = matches
        .get_one::<String>("quorum-size")
        .context("required --quorum-size argument not provided")?
        .parse()
        .context("--quorum-size argument was not an unsigned integer")?;
    let num_shards: u32 = matches
        .get_one::<String>("shards")
        .context("required --quorum-size argument not provided")?
        .parse()
        .context("--shards argument was not an unsigned integer")?;
    let input_path = matches
        .get_one::<String>("INPUT")
        .context("required INPUT argument not provided")?;

    validate_shard_counts(quorum_size, num_shards)?;

    let (mut stdin_reader, mut file_reader);
    let input: &mut dyn Read = if input_path == "-" {
        stdin_reader = io::stdin();
        &mut stdin_reader
    } else {
        file_reader = File::open(input_path)
            .with_context(|| format!("failed to open secret data file '{}'", input_path))?;
        &mut file_reader
    };
    let mut buffer_input = BufReader::new(input);

    let mut secret = Vec::new();
    buffer_input
        .read_to_end(&mut secret)
        .with_context(|| format!("failed to read secret data from '{}'", input_path))?;

    let backup = if sealed {
        Backup::new_sealed(quorum_size, &secret)
    } else {
        Backup::new(quorum_size, &secret)
    }?;
    let main_document = backup.main_document().clone();
    let shards = (0..num_shards)
        .map(|_| backup.next_shard().unwrap())
        .map(|s| (s.id(), s.encrypt().unwrap()))
        .collect::<Vec<_>>();

    main_document
        .to_pdf()?
        .save(&mut BufWriter::new(File::create(format!(
            "main_document-{}.pdf",
            main_document.id()
        ))?))?;

    for (shard_id, (shard, codewords)) in shards {
        (shard, codewords)
            .to_pdf()?
            .save(&mut BufWriter::new(File::create(format!(
                "key_shard-{}-{}.pdf",
                main_document.id(),
                shard_id
            ))?))?;
    }

    if matches.get_flag("print-data") {
        eprintln!("WARNING: printing main document payload to stdout; this is sensitive data.");
        for line in main_document.debug_qr_data_strings()? {
            println!("{}", line);
        }
    }

    Ok(())
}

/// Adds the shared `--echo`/`--no-echo` flags to a subcommand that prompts
/// interactively for codewords or shard/document data. Exactly one (or
/// neither) may be given; see `resolve_echo`.
pub(crate) fn add_echo_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("echo")
            .long("echo")
            .help("Echo typed codewords and shard/document data to the terminal (old behavior). Has no effect when stdin is not a TTY, since piped input was never echoed to begin with.")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("no-echo")
            .long("no-echo")
            .help("Do not echo typed codewords and shard/document data to the terminal. This is already the default when reading interactively from a terminal.")
            .action(ArgAction::SetTrue),
    )
    .group(ArgGroup::new("echo-mode").args(["echo", "no-echo"]))
}

/// Resolves the effective echo setting for a subcommand carrying the
/// `--echo`/`--no-echo` flags added by `add_echo_args`.
///
/// Terminal echo is suppressed by default: codewords and shard/main-document
/// payloads typed at an interactive prompt are exactly the data needed to
/// recover the secret, and leaving all of it in one terminal's scrollback
/// defeats the purpose of splitting the secret into shards. Piped,
/// non-interactive input is unaffected by these flags: echo control has no
/// meaning there, and (unlike stated in earlier design notes) the
/// echo-suppressed read path talks to the controlling terminal directly
/// rather than to stdin, so it must not be used unless stdin actually is
/// that terminal -- otherwise piped input would be silently ignored.
pub(crate) fn resolve_echo(matches: &ArgMatches) -> bool {
    if matches.get_flag("echo") {
        true
    } else if matches.get_flag("no-echo") {
        false
    } else {
        !io::stdin().is_terminal()
    }
}

/// Reads a single line of secret input (one codeword line, or one line of a
/// multibase payload), returning `Ok(None)` at EOF.
///
/// Echo is only ever suppressed when stdin is confirmed to be an
/// interactive terminal; otherwise (whether `echo` is true, or stdin is a
/// pipe) this reads a plain line from stdin exactly as before.
pub(crate) fn read_secret_line(echo: bool) -> Result<Option<String>, Error> {
    if echo || !io::stdin().is_terminal() {
        let mut buf = String::new();
        return match io::stdin().read_line(&mut buf) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(buf.trim_end_matches(['\n', '\r']).to_string())),
            Err(err) => Err(anyhow!("failed to read data: {}", err)),
        };
    }

    match rpassword::read_password() {
        Ok(line) => Ok(Some(line)),
        // rpassword surfaces a plain io::Error (e.g. unexpected EOF, or no
        // controlling terminal available); treat any failure to read a line
        // the same way an empty line is treated below, rather than
        // propagating a hard error out of an interactive prompt.
        Err(_) => Ok(None),
    }
}

/// Reads lines via `next_line` until an empty line or EOF, joining what was
/// read with `\n`. Factored out of `read_multiline` so the "blank line
/// terminates" logic is unit-testable without a real (or even piped) stdin.
fn read_lines_until_blank(
    mut next_line: impl FnMut() -> Result<Option<String>, Error>,
) -> Result<String, Error> {
    let mut lines = Vec::new();
    loop {
        match next_line()? {
            Some(line) if !line.is_empty() => lines.push(line),
            _ => break,
        }
    }
    Ok(lines.join("\n"))
}

fn read_multiline<S: AsRef<str>>(prompt: S, echo: bool) -> Result<String, Error> {
    if !echo && io::stdin().is_terminal() {
        println!("(input will not be echoed; enter a blank line to finish)");
    }
    print!("{}: ", prompt.as_ref());
    io::stdout().flush()?;

    read_lines_until_blank(|| read_secret_line(echo))
}

fn read_multibase<S: AsRef<str>, T: FromWire>(prompt: S, echo: bool) -> Result<T, Error> {
    T::from_wire_multibase(
        wire::multibase_strip(read_multiline(prompt, echo)?)
            .map_err(|err| anyhow!("failed to strip out non-multibase characters: {}", err))?,
    )
    .map_err(|err| anyhow!("failed to parse data: {}", err))
}

fn read_codewords<S: AsRef<str>>(prompt: S, echo: bool) -> Result<KeyShardCodewords, Error> {
    Ok(read_multiline(prompt, echo)?
        .split_whitespace()
        .map(|s| s.to_owned())
        .collect::<Vec<_>>())
}

fn read_multibase_qr<S: AsRef<str>, T: FromWire>(prompt: S, echo: bool) -> Result<T, Error> {
    let prompt = prompt.as_ref();
    let mut joiner = qr::Joiner::new();
    while !joiner.complete() {
        let part: qr::Part = read_multibase(
            format!(
                "{} ({} codes remaining)",
                prompt,
                match joiner.remaining() {
                    None => "unknown number of".to_string(),
                    Some(n) => n.to_string(),
                }
            ),
            echo,
        )?;
        joiner.add_part(part)?;
    }
    T::from_wire(joiner.combine_parts()?)
        .map_err(|err| anyhow!("parse inner qr code data: {}", err))
}

// paperback-cli recover --interactive
fn recover_cli() -> Command {
    add_echo_args(
        Command::new("recover")
            .about(r#"Recover a paperback backup."#)
            .arg(
                Arg::new("interactive")
                    .long("interactive")
                    .help("Ask for data stored in QR codes interactively rather than scanning images.")
                    .action(ArgAction::SetTrue)
                    // TODO: Make this optional.
                    .required(true),
            )
            .arg(
                Arg::new("OUTPUT")
                    .help(r#"Path to write recovered secret data to ("-" to write to stdout)."#)
                    .action(ArgAction::Set)
                    .allow_hyphen_values(true)
                    .required(true)
                    .index(1),
            ),
    )
}

fn recover(matches: &ArgMatches) -> Result<(), Error> {
    let interactive = matches.get_flag("interactive");
    ensure!(interactive, "PDF scanning not yet implemented");
    let echo = resolve_echo(matches);
    let output_path = matches
        .get_one::<String>("OUTPUT")
        .context("required OUTPUT argument not provided")?;

    let main_document: MainDocument = read_multibase_qr("Enter a main document code", echo)?;
    let quorum_size = main_document.quorum_size();
    // TODO: Ask the user to input the checksum...
    println!(
        "Main document checksum: {}",
        main_document.checksum_string()
    );

    println!("Document ID: {}", main_document.id());
    println!("{} key shards required.", quorum_size);

    let mut quorum = UntrustedQuorum::new();
    quorum.main_document(main_document);
    while quorum.num_untrusted_shards() < quorum_size as usize {
        let idx = quorum.num_untrusted_shards() as u32;
        let encrypted_shard: EncryptedKeyShard = read_multibase(
            format!(
                "Quorum contains [{}] key shards.\nEnter key shard {} of {}",
                quorum
                    .untrusted_shards()
                    .map(KeyShard::id)
                    .collect::<Vec<_>>()
                    .join(" "),
                idx + 1,
                quorum_size
            ),
            echo,
        )?;
        // TODO: Ask the user to input the checksum...
        println!(
            "Key shard {} checksum: {}",
            idx + 1,
            encrypted_shard.checksum_string()
        );

        let codewords = read_codewords(format!("Enter key shard {} codewords", idx + 1), echo)?;
        let shard = encrypted_shard
            .decrypt(&codewords)
            .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
            .with_context(|| format!("decrypting key shard {}", idx + 1))?;

        println!("Loaded key shard {}.", shard.id());
        quorum.push_shard(shard);
    }

    let quorum = quorum.validate().map_err(|err| {
        anyhow!(
            "quorum failed to validate -- possible forgery! {}; groupings: {:?}",
            err.message,
            err.as_groups()
        )
    })?;

    let secret = quorum
        .recover_document()
        .context("recovering secret data")?;

    let (mut stdout_writer, mut file_writer);
    let output_file: &mut dyn Write = if output_path == "-" {
        stdout_writer = io::stdout();
        &mut stdout_writer
    } else {
        file_writer = File::create(output_path)
            .with_context(|| format!("failed to open output file '{}' for writing", output_path))?;
        &mut file_writer
    };

    output_file
        .write_all(&secret)
        .context("write secret data to file")?;

    Ok(())
}

fn new_shards(
    new_shard_types: impl IntoIterator<Item = NewShardKind>,
    echo: bool,
) -> Result<(), Error> {
    let mut quorum = UntrustedQuorum::new();
    loop {
        let idx = quorum.num_untrusted_shards() as u32;
        let encrypted_shard: EncryptedKeyShard = read_multibase(
            match quorum.quorum_size() {
                None => format!(
                    "Quorum contains no key shards.\nEnter key shard {}",
                    idx + 1
                ),
                Some(n) => format!(
                    "Quorum contains [{}] key shards.\nEnter key shard {} of {}",
                    quorum
                        .untrusted_shards()
                        .map(KeyShard::id)
                        .collect::<Vec<_>>()
                        .join(" "),
                    idx + 1,
                    n,
                ),
            },
            echo,
        )?;
        // TODO: Ask the user to input the checksum...
        println!(
            "Key shard {} checksum: {}",
            idx + 1,
            encrypted_shard.checksum_string()
        );

        let codewords = read_codewords(format!("Enter key shard {} codewords", idx + 1), echo)?;
        let shard = encrypted_shard
            .decrypt(&codewords)
            .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
            .with_context(|| format!("decrypting key shard {}", idx + 1))?;

        println!("Loaded key shard {}.", shard.id());
        quorum.push_shard(shard);

        if idx + 1
            >= quorum
                .quorum_size()
                .expect("quorum_size should be set after adding a key shard")
        {
            break;
        }
    }

    let quorum = quorum.validate().map_err(|err| {
        anyhow!(
            "quorum failed to validate -- possible forgery! {}; groupings: {:?}",
            err.message,
            err.as_groups()
        )
    })?;

    let new_shards = new_shard_types
        .into_iter()
        .map(|new| {
            let s = quorum.new_shard(new).context("minting new key shards")?;
            Ok((
                s.document_id(),
                s.id(),
                s.encrypt().expect("encrypt new shard"),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    for (document_id, shard_id, (shard, codewords)) in new_shards {
        (shard, codewords)
            .to_pdf()?
            .save(&mut BufWriter::new(File::create(format!(
                "key_shard-{}-{}.pdf",
                document_id, shard_id
            ))?))?;
    }

    Ok(())
}

// paperback-cli expand-shards --interactive -n <SHARDS>
fn expand_shards_cli() -> Command {
    add_echo_args(
        Command::new("expand-shards")
            .about(r#"Create new key shards from a quorum of old key shards. The new key shards are separate to existing key shards, which means you are increasing the number of shards in circulation. This operation is recommended when you wish to add a new key shard holder to an existing quorum (and you are still confident that no more than N-1 shard holders will conspire against you)."#)
            .arg(Arg::new("interactive")
                .long("interactive")
                .help(r#"Ask for data stored in QR codes interactively rather than scanning images."#)
                .action(ArgAction::SetTrue)
                // TODO: Make this optional.
                .required(true))
            .arg(Arg::new("new-shards")
                .short('n')
                .long("new-shards")
                .value_name("NUM SHARDS")
                .help(r#"Number of new shards to create."#)
                .action(ArgAction::Set)
                .required(true)),
    )
}

fn expand_shards(matches: &ArgMatches) -> Result<(), Error> {
    let num_new_shards: u32 = matches
        .get_one::<String>("new-shards")
        .context("required --new-shards argument not provided")?
        .parse()
        .context("--new-shards argument was not an unsigned integer")?;
    new_shards(
        (0..num_new_shards).map(|_| NewShardKind::NewShard),
        resolve_echo(matches),
    )
}

// paperback-cli recreate-shards --interactive <SHARD-ID>...
fn recreate_shards_cli() -> Command {
    add_echo_args(
        Command::new("recreate-shards")
            .about(r#"Re-create key shards with a given identifier from a quorum of old key shards. The re-created key shards are identical to the original versions of said key shards. This operation is recommended when one of the key shard holders lose their key shard and need a replacement (this ensures that they cannot fool you into getting an distinct new shard in addition to the original)."#)
            .arg(Arg::new("interactive")
                .long("interactive")
                .help(r#"Ask for data stored in QR codes interactively rather than scanning images."#)
                .action(ArgAction::SetTrue)
                // TODO: Make this optional.
                .required(true))
            .arg(Arg::new("shard-ids")
                .value_name("SHARD ID")
                .help(r#"Shard identifier(s) of the shard(s) to recreate."#)
                .value_parser(|s: &str| {
                    paperback::validate_shard_id(s)
                        .map(|()| s.to_string())
                        .map_err(|err| format!("invalid shard id {s:?}: {err}"))
                })
                .action(ArgAction::Append)
                .required(true)),
    )
}

fn recreate_shards(matches: &ArgMatches) -> Result<(), Error> {
    let new_shard_list = matches
        .get_many::<String>("shard-ids")
        .context("required shard id arguments not given")?
        .cloned()
        .map(NewShardKind::ExistingShard);
    new_shards(new_shard_list, resolve_echo(matches))
}

// paperback-cli reprint --interactive [--main-document|--shard]
fn reprint_cli() -> Command {
    add_echo_args(
        Command::new("reprint")
            .about(r#""Re-print" a paperback document by generating a new PDF from an existing PDF."#)
            .arg(
                Arg::new("interactive")
                    .long("interactive")
                    .help("Ask for data stored in QR codes interactively rather than scanning images.")
                    .action(ArgAction::SetTrue)
                    // TODO: Make this optional.
                    .required(true),
            )
            .arg(
                Arg::new("main-document")
                    .long("main-document")
                    .help(r#"Reprint a paperback main document."#)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("shard")
                    .long("shard")
                    .help(r#"Reprint a paperback key shard."#)
                    .action(ArgAction::SetTrue),
            )
            .group(
                ArgGroup::new("type")
                    .arg("main-document")
                    .arg("shard")
                    .required(true),
            )
            .arg(Arg::new("print-data")
                .long("print-data")
                .help("When reprinting a main document, also print its encrypted QR payload to stdout. This is sensitive data -- only use this until PDF scanning is implemented and you need the text form back without a scanner. Has no effect with --shard.")
                .action(ArgAction::SetTrue)),
    )
}

fn reprint(matches: &ArgMatches) -> Result<(), Error> {
    let interactive = matches.get_flag("interactive");
    ensure!(interactive, "PDF scanning not yet implemented");
    let echo = resolve_echo(matches);

    let mut main_document: MainDocument;
    let mut shard_pair: (EncryptedKeyShard, KeyShardCodewords);
    let mut main_document_payload: Option<Vec<String>> = None;
    let (pdf, path_basename): (&mut dyn ToPdf, String) = match matches
        .get_one::<clap::Id>("type")
        .context("neither --main-document nor --shard provided")?
        .as_str()
    {
        "main-document" => {
            main_document = read_multibase_qr("Enter a main document code", echo)?;
            // TODO: Ask the user to input the checksum...
            println!(
                "Main document checksum: {}",
                main_document.checksum_string()
            );

            if matches.get_flag("print-data") {
                main_document_payload = Some(main_document.debug_qr_data_strings()?);
            }

            let pathname = format!("main-document-{}.pdf", main_document.id());
            (&mut main_document, pathname)
        }
        "shard" => {
            let encrypted_shard: EncryptedKeyShard = read_multibase("Enter key shard", echo)?;
            // TODO: Ask the user to input the checksum...
            println!("Key shard checksum: {}", encrypted_shard.checksum_string());
            let codewords = read_codewords("Key shard codewords", echo)?;

            let shard = encrypted_shard
                .decrypt(codewords.clone())
                .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
                .with_context(|| "decrypting shard")?;
            let pathname = format!("key-shard-{}-{}.pdf", shard.document_id(), shard.id());

            shard_pair = (encrypted_shard, codewords);
            (&mut shard_pair, pathname)
        }
        // We should never reach here.
        _ => bail!("neither --shard nor --main-document type flags passed"),
    };

    pdf.to_pdf()?
        .save(&mut BufWriter::new(File::create(path_basename)?))?;

    match main_document_payload {
        Some(lines) => {
            eprintln!("WARNING: printing main document payload to stdout; this is sensitive data.");
            for line in lines {
                println!("{}", line);
            }
        }
        None if matches.get_flag("print-data") => {
            eprintln!("--print-data has no effect when reprinting a key shard.");
        }
        None => {}
    }

    Ok(())
}

fn cli() -> Command {
    Command::new("paperback-cli")
        .version("0.0.0")
        .author("Aleksa Sarai <cyphar@cyphar.com>")
        .about("Operate on a paperback backup using a basic CLI interface.")
        // paperback-cli backup [--sealed] -n <QUORUM SIZE> -k <SHARDS> INPUT
        .subcommand(backup_cli())
        // paperback-cli recover --interactive
        .subcommand(recover_cli())
        // paperback-cli expand-shards --interactive -n <SHARDS>
        .subcommand(expand_shards_cli())
        // paperback-cli recreate-shards --interactive <SHARD-ID>...
        .subcommand(recreate_shards_cli())
        // paperback-cli reprint --interactive [--main-document|--shard]
        .subcommand(reprint_cli())
        // paperback-cli raw ...
        .subcommand(raw::subcommands())
}

fn main() -> Result<(), Box<dyn StdError>> {
    let mut app = cli();

    match app.get_matches_mut().subcommand() {
        Some(("raw", sub_matches)) => raw::submatch(&mut app, sub_matches),
        Some(("backup", sub_matches)) => backup(sub_matches),
        Some(("recover", sub_matches)) => recover(sub_matches),
        Some(("expand-shards", sub_matches)) => expand_shards(sub_matches),
        Some(("recreate-shards", sub_matches)) => recreate_shards(sub_matches),
        Some(("reprint", sub_matches)) => reprint(sub_matches),
        Some((subcommand, _)) => {
            // We should never end up here.
            app.print_help()?;
            Err(anyhow!("unknown subcommand '{}'", subcommand))
        }
        None => {
            app.print_help()?;
            Err(anyhow!("no subcommand specified"))
        }
    }?;

    Ok(())
}

#[test]
fn verify_cli() {
    cli().debug_assert();
}

#[test]
fn main_recreate_shards_cli_rejects_invalid_shard_id() {
    // A shard id that decodes to more than 4 bytes must be rejected by the
    // clap value_parser immediately -- before any interactive shard entry is
    // attempted -- rather than reaching GfElem::from_bytes and panicking.
    let oversized_id = multibase::encode(multibase::Base::Base32Z, [1u8, 2, 3, 4, 5]);
    let err = cli()
        .try_get_matches_from([
            "paperback-cli",
            "recreate-shards",
            "--interactive",
            &oversized_id,
        ])
        .expect_err("oversized shard id should be rejected at argument-parse time");
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
}

#[cfg(test)]
mod validate_shard_counts_test {
    use super::validate_shard_counts;

    #[test]
    fn rejects_shards_below_quorum() {
        let err = validate_shard_counts(5, 2).unwrap_err();
        assert!(err.to_string().contains("unrecoverable"));
    }

    #[test]
    fn rejects_zero_shards() {
        assert!(validate_shard_counts(1, 0).is_err());
    }

    #[test]
    fn rejects_zero_quorum() {
        let err = validate_shard_counts(0, 0).unwrap_err();
        assert!(err.to_string().contains("quorum-size must be at least 1"));
    }

    #[test]
    fn accepts_equal_shards_and_quorum() {
        assert!(validate_shard_counts(3, 3).is_ok());
    }

    #[test]
    fn accepts_more_shards_than_quorum() {
        assert!(validate_shard_counts(2, 5).is_ok());
    }
}

#[cfg(test)]
mod echo_args_test {
    use super::cli;

    #[test]
    fn echo_and_no_echo_are_mutually_exclusive() {
        let err = cli()
            .try_get_matches_from([
                "paperback-cli",
                "recover",
                "--interactive",
                "--echo",
                "--no-echo",
                "-",
            ])
            .expect_err("--echo and --no-echo together should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}

#[cfg(test)]
mod read_lines_until_blank_test {
    use super::read_lines_until_blank;

    // read_lines_until_blank() is the terminating logic behind every
    // interactive multiline prompt (codewords, shard/document payloads),
    // with the actual line source abstracted behind a closure. This is what
    // makes it testable without a real (or even piped) stdin: feed it a
    // canned sequence of `Ok(Some(..))`/`Ok(None)` values, exactly the shape
    // a piped, non-TTY read would produce.

    fn lines_source(
        lines: Vec<Option<&'static str>>,
    ) -> impl FnMut() -> Result<Option<String>, anyhow::Error> {
        let mut lines = lines.into_iter();
        move || Ok(lines.next().flatten().map(|s| s.to_string()))
    }

    #[test]
    fn stops_on_blank_line() {
        let result = read_lines_until_blank(lines_source(vec![
            Some("first"),
            Some("second"),
            Some(""),
            Some("never read"),
        ]))
        .unwrap();
        assert_eq!(result, "first\nsecond");
    }

    #[test]
    fn handles_eof_without_blank_line() {
        // No blank line before the source is exhausted (`None` = EOF) --
        // this must terminate and return what was read so far, not hang or
        // error, mirroring the pre-existing `Err(_)`-also-terminates
        // behavior of the original take_while-based implementation.
        let result = read_lines_until_blank(lines_source(vec![Some("only line"), None])).unwrap();
        assert_eq!(result, "only line");
    }

    #[test]
    fn empty_input_yields_empty_string() {
        let result = read_lines_until_blank(lines_source(vec![None])).unwrap();
        assert_eq!(result, "");
    }
}

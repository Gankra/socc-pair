use error_chain::error_chain;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{copy, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{crate_version, App, AppSettings, Arg};
use log::error;
use simplelog::{
    ColorChoice, ConfigBuilder, Level, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};

error_chain! {
     foreign_links {
         Io(std::io::Error);
         HttpRequest(reqwest::Error);
     }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("socc-pair")
        .version(crate_version!())
        .about("Compares two minidump-stackwalk json outputs (usually socorro vs local)")
        .setting(AppSettings::NextLineHelp)
        .setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .default_value("error")
                .takes_value(true)
                .long_help(
                    "Set the level of verbosity (off, error (default), warn, info, debug, trace)",
                ),
        )
        .arg(
            Arg::with_name("ignore-field")
                .multiple(true)
                .long("ignore-field")
                .takes_value(true)
                .long_help(
                    "Fields in the json output to ignore the value of during comparison.

If no values are provided, the default ignores will be:

deprecated fields:
  * frames_truncated
  * tiny_block_size
  * write_combine_size
  * largest_free_vm_block

redundant fields:
  * total_frames
  * frame_count
  * threads_index

debugging fields:
  * missing_symbols
  * symbol_disk_cache_hit
  * symbol_url
  * loaded_symbols

A warning will still be emitted for ignored fields. This is useful for deprecated fields \
which you don't care about the value of, or fields which contain redundant data like
the length of an array.\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("compare")
                .long("compare")
                .takes_value(true)
                .long_help(
                    "A subfield of the json output to focus the comparison on.

If no value is provided, the whole json will be compared.

--compare=threads will only compare the backtraces, which is useful.\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("raw-json")
                .long("raw-json")
                .default_value("socorro")
                .takes_value(true)
                .long_help(
                    "An input JSON file with the extra information.

Possible values:
* 'socorro' (default) - Get the 'raw' JSON from socorro 
  (API token may require 'View Personal Identifiable Information') 
* 'none' - Do not use a raw-json
* <anything else> - assumed to be a path to a local raw-json file

This is a gross hack for some legacy side-channel information that mozilla uses. It will \
hopefully be phased out and deprecated in favour of just using custom streams in the \
minidump itself.\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("socorro-cache")
                .long("socorro-cache")
                .takes_value(true)
                .long_help(
                    "Where to cache files downloaded from socorro.

Defaults to std::env::temp_dir()/socc-pair/dumps/

This includes:

* minidumps (as $CRASH_ID.dmp)
* processed crash json (as $CRASH_ID.json)
* raw json (as $CRASH_ID.raw.json)

The output of the local minidump-stackwalk will also be saved here, for convenience:

* output (as $CRASH_ID.local.json)
* logs (as $CRASH_ID.log.txt)

socc-pair will output all these paths at the end of its output.\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("symbols-url")
                .multiple(true)
                .long("symbols-url")
                .default_value("https://symbols.mozilla.org/")
                .takes_value(true)
                .long_help(
                    "base URL from which URLs to symbol files can be constructed.

If multiple symbols-url values are provided, they will each be tried in order until \
one resolves.

The server the base URL points to is expected to conform to the Tecken \
symbol server protocol. For more details, see the Tecken docs:

https://tecken.readthedocs.io/en/latest/

Example symbols-url value: https://symbols.mozilla.org/\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("symbols-cache")
                .long("symbols-cache")
                .takes_value(true)
                .long_help(
                    "A directory in which downloaded symbols can be stored.
                    
Symbol files can be very large, so we recommend placing cached files in your \
system's temp directory so that it can garbage collect unused ones for you. \
To this end, the default value for this flag is a `rust-minidump-cache` \
subdirectory of `std::env::temp_dir()` (usually /tmp/rust-minidump-cache on linux).

symbols-cache must be on the same filesystem as symbols-tmp (if that doesn't mean anything to \
you, don't worry about it, you're probably not doing something that will run afoul of it).
\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("symbols-tmp")
                .long("symbols-tmp")
                .takes_value(true)
                .long_help(
                    "A directory to use as temp space for downloading symbols.

A temp dir is necessary to allow for multiple rust-minidump instances to share a cache without \
race conditions. Files to be added to the cache will be constructed in this location before \
being atomically moved to the cache.

If no path is specified, `std::env::temp_dir()` will be used to improve portability. \
See the rust documentation for how to set that value if you wish to use something other than \
your system's default temp directory.

symbols-tmp must be on the same filesystem as symbols-cache (if that doesn't mean anything to \
you, don't worry about it, you're probably not doing something that will run afoul of it).
\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("output-file")
                .long("output-file")
                .takes_value(true)
                .help("Where to write the output to (if unspecified, stdout is used)"),
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .takes_value(true)
                .help("Where to write logs to (if unspecified, stderr is used)"),
        )
        .arg(
            Arg::with_name("api-token")
                .long("api-token")
                .takes_value(true)
                .required(true)
                .long_help(
                    "A socorro api token to use for getting minidumps

Required permissions:

* 'View Raw Dumps' (hard required)
* 'View Personal Identifiable Information' (to read some entries in raw-json)

See https://crash-stats.mozilla.org/api/tokens/ for details.
\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("crash-id")
                .long("crash-id")
                .takes_value(true)
                .required(true)
                .long_help(
                    "The socorro crash id to analyze
\n\n\n",
                ),
        )
        .after_help(
            "


",
        )
        .get_matches();

    let output_file = matches
        .value_of_os("output-file")
        .map(|os_str| Path::new(os_str).to_owned());

    let log_file = matches
        .value_of_os("log-file")
        .map(|os_str| Path::new(os_str).to_owned());

    let verbosity = match matches.value_of("verbose").unwrap() {
        "off" => LevelFilter::Off,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Error,
    };

    // Init the logger (and make trace logging less noisy)
    if let Some(log_path) = log_file {
        let log_file = File::create(log_path).unwrap();
        let _ = WriteLogger::init(
            verbosity,
            ConfigBuilder::new()
                .set_location_level(LevelFilter::Off)
                .set_time_level(LevelFilter::Off)
                .set_thread_level(LevelFilter::Off)
                .set_target_level(LevelFilter::Off)
                .build(),
            log_file,
        )
        .unwrap();
    } else {
        let _ = TermLogger::init(
            verbosity,
            ConfigBuilder::new()
                .set_location_level(LevelFilter::Off)
                .set_time_level(LevelFilter::Off)
                .set_thread_level(LevelFilter::Off)
                .set_target_level(LevelFilter::Off)
                .set_level_color(Level::Trace, None)
                .build(),
            TerminalMode::Stderr,
            ColorChoice::Auto,
        );
    }

    let temp_dir = std::env::temp_dir();

    // Default to env::temp_dir()/socc-pair/dumps
    let dump_cache = matches
        .value_of_os("socorro-cache")
        .map(|os_str| Path::new(os_str).to_owned())
        .unwrap_or_else(|| temp_dir.join("socc-pair").join("dumps"));

    // Default to env::temp_dir()/rust-minidump-cache
    let symbols_cache = matches
        .value_of_os("symbols-cache")
        .map(|os_str| Path::new(os_str).to_owned())
        .unwrap_or_else(|| temp_dir.join("rust-minidump-cache"));

    // Default to env::temp_dir()
    let symbols_tmp = matches
        .value_of_os("symbols-tmp")
        .map(|os_str| Path::new(os_str).to_owned())
        .unwrap_or(temp_dir);

    let symbols_urls = matches
        .values_of("symbols-url")
        .map(|v| v.map(String::from).collect::<Vec<_>>())
        .unwrap_or_else(Vec::new);

    let raw_json_arg = matches.value_of_os("raw-json").expect("Missing raw json");

    let api_token = matches.value_of("api-token").expect("Missing API token");

    let crash_id = matches.value_of("crash-id").expect("Missing crash-id");

    let default_ignored_fields = [
        // deprecated
        "frames_truncated",
        "tiny_block_size",
        "write_combine_size",
        "largest_free_vm_block",
        // redundant
        "total_frames",
        "frame_count",
        "threads_index",
        // execution debugging
        "missing_symbols",
        "symbol_disk_cache_hit",
        "symbol_url",
        "loaded_symbols",
    ];

    let ignored_fields = matches
        .values_of("ignore-field")
        .map(|s| s.collect::<Vec<_>>());

    let ignored_fields = ignored_fields
        .as_ref()
        .map(|v| v.as_slice())
        .unwrap_or(&default_ignored_fields)
        .iter()
        .copied()
        .collect::<HashSet<&str>>();

    let compare_field = matches.value_of("compare");

    // Ensure the dump cache exists
    fs::create_dir_all(&dump_cache)?;

    // output paths to report:
    // * minidump (the minidump to analyze)
    // * socc_output (socorro processed crash)
    // * raw_json ("raw" json file)
    // * local_output (local minidump-stackwalk output)
    // * local_logs (local minidump-stackwalk log output)

    let mut local_output = dump_cache.join(&crash_id);
    local_output.set_extension("local.json");

    let mut local_logs = dump_cache.join(&crash_id);
    local_logs.set_extension("log.txt");

    // Download the minidump
    let minidump_req = reqwest::Client::new()
        .get("https://crash-stats.mozilla.org/api/RawCrash/")
        .header("Auth-Token", api_token)
        .query(&[
            ("crash_id", crash_id),
            ("format", "raw"),
            ("name", "upload_file_minidump"),
        ]);

    let mut minidump = dump_cache.join(&crash_id);
    minidump.set_extension("dmp");

    fetch(minidump_req, &minidump).await?;

    // Download the json socorro has for the minidump
    let socc_output_req = reqwest::Client::new()
        .get("https://crash-stats.mozilla.org/api/ProcessedCrash/")
        .header("Auth-Token", api_token)
        .query(&[("crash_id", crash_id)]);
    let mut socc_output = dump_cache.join(&crash_id);
    socc_output.set_extension("json");

    let socc_json = fetch(socc_output_req, &socc_output).await?;
    let socc_json: serde_json::Value = serde_json::from_reader(BufReader::new(socc_json)).unwrap();
    let socc_json = socc_json.get("json_dump").unwrap();

    // Get the "raw" json file with things like certificate info
    let raw_json = if raw_json_arg == OsStr::new("none") {
        // Don't use raw json
        None
    } else if raw_json_arg == OsStr::new("socorro") {
        // Download the raw json from socorro
        let extra_json_req = reqwest::Client::new()
            .get("https://crash-stats.mozilla.org/api/RawCrash/")
            .header("Auth-Token", api_token)
            .query(&[("crash_id", crash_id)]);
        let mut extra_json_path = dump_cache.join(&crash_id);
        extra_json_path.set_extension("raw.json");

        // Just need it on disk for rust-minidump, don't actually need the value here.
        let _extra_json = fetch(extra_json_req, &extra_json_path).await?;

        Some(extra_json_path)
    } else {
        // Assume --raw-json is a local path
        Some(PathBuf::from(raw_json_arg))
    };

    // Process the minidump with local minidump-stackwalk
    println!("analyzing...");
    let mut command = &mut Command::new("minidump-stackwalk");

    if let Some(raw_json) = &raw_json {
        let mut arg = OsString::from("--raw-json=");
        arg.push(&raw_json);
        command = command.arg(arg);
    }

    for url in symbols_urls {
        let mut arg = OsString::from("--symbols-url=");
        arg.push(&url);
        command = command.arg(arg);
    }

    {
        let mut arg = OsString::from("--symbols-cache=");
        arg.push(&symbols_cache);
        command = command.arg(arg);
    }

    {
        let mut arg = OsString::from("--symbols-tmp=");
        arg.push(&symbols_tmp);
        command = command.arg(arg);
    }

    {
        let mut arg = OsString::from("--output-file=");
        arg.push(&local_output);
        command = command.arg(arg);
    }

    {
        let mut arg = OsString::from("--log-file=");
        arg.push(&local_logs);
        command = command.arg(arg);
    }

    let _ = command
        .arg(&minidump)
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    println!("analyzed!");

    let rust_json_file = File::open(&local_output).unwrap();
    let rust_json: serde_json::Value =
        serde_json::from_reader(BufReader::new(rust_json_file)).unwrap();

    compare_crashes(compare_field, &ignored_fields, &socc_json, &rust_json);

    println!("\nOutput Files: ");
    println!("  * Minidump: {}", minidump.display());
    println!("  * Socorro Processed Crash: {}", socc_output.display());
    if let Some(raw_json) = &raw_json {
        println!("  * Raw JSON: {}", raw_json.display());
    }
    println!(
        "  * Local minidump-stackwalk Output: {}",
        local_output.display()
    );
    println!(
        "  * Local minidump-stackwalk Logs: {}",
        local_logs.display()
    );

    Ok(())
}

fn compare_crashes(
    compare_field: Option<&str>,
    ignored_fields: &HashSet<&str>,
    socc_json: &serde_json::Value,
    rust_json: &serde_json::Value,
) {
    let (field, socc, rust) = if let Some(field) = compare_field {
        // Only analyze this subfield
        (
            field,
            socc_json.get(field).unwrap(),
            rust_json.get(field).unwrap(),
        )
    } else {
        // Analyze the whole output
        ("", socc_json, rust_json)
    };

    println!("");
    let (errors, warnings) = recursive_compare(0, field, socc, rust, ignored_fields);
    let status = if errors == 0 { "+" } else { "-" };
    println!("");
    println!(
        "{} Total errors: {}, warnings: {}",
        status, errors, warnings
    );
}

fn recursive_compare(
    depth: usize,
    k: &str,
    socc_val: &serde_json::Value,
    rust_val: &serde_json::Value,
    ignored: &HashSet<&str>,
) -> (u64, u64) {
    use serde_json::Value::*;

    let mut errors = 0;
    let mut warnings = 0;

    // These fields are either redundant or unimportant. Treat them being missing as only
    // a warning to allow us to focus on more significant problems.

    match (socc_val, rust_val) {
        (Bool(s), Bool(r)) => {
            if s == r {
                println!(" {:width$}{}: {}", "", k, s, width = depth);
            } else if ignored.contains(&k) {
                warnings += 1;
                println!("~{:width$}ignoring field {}: {}", "", k, s, width = depth);
            } else {
                errors += 1;
                println!("-{:width$}did not match", "", width = depth);
                println!("+{:width$}{}: {}", "", k, s, width = depth);
                println!("-{:width$}{}: {}", "", k, r, width = depth);
            }
        }
        (Number(s), Number(r)) => {
            if s == r {
                println!(" {:width$}{}: {}", "", k, s, width = depth);
            } else if ignored.contains(&k) {
                warnings += 1;
                println!("~{:width$}ignoring field {}: {}", "", k, s, width = depth);
            } else {
                errors += 1;
                println!("-{:width$}did not match", "", width = depth);
                println!("+{:width$}{}: {}", "", k, s, width = depth);
                println!("-{:width$}{}: {}", "", k, r, width = depth);
            }
        }
        (String(s), String(r)) => {
            if let (Some(s), Some(r)) = (parse_int(s), parse_int(r)) {
                if s == r {
                    println!(" {:width$}{}: 0x{:08x}", "", k, s, width = depth);
                } else {
                    errors += 1;
                    println!("-{:width$}did not match", "", width = depth);
                    println!("+{:width$}{}: 0x{:08x}", "", k, s, width = depth);
                    println!("-{:width$}{}: 0x{:08x}", "", k, r, width = depth);
                }
            } else {
                if s == r {
                    println!(" {:width$}{}: {}", "", k, s, width = depth);
                } else if k == "trust" {
                    let (s_trust, r_trust) = trust_levels(socc_val, rust_val);
                    if r_trust < s_trust {
                        println!(
                            "~{:width$}rust had better trust ({} vs {})",
                            "",
                            s,
                            r,
                            width = depth
                        );
                        warnings += 1;
                    } else if s_trust < r_trust {
                        println!(
                            "-{:width$}socc had better trust ({} vs {})",
                            "",
                            s,
                            r,
                            width = depth
                        );
                        errors += 1;
                    } else {
                        // Shouldn't be possible? I want to know if this happens.
                        unreachable!()
                    }
                } else {
                    errors += 1;
                    println!("-{:width$}did not match", "", width = depth);
                    println!("+{:width$}{}: {}", "", k, s, width = depth);
                    println!("-{:width$}{}: {}", "", k, r, width = depth);
                }
            }
        }
        (Object(s), Object(r)) => {
            println!("{:width$} {}: {{", "", k, width = depth);
            let new_depth = depth + 2;
            for (k, s) in s {
                if let Some(r) = r.get(k) {
                    let (new_errors, new_warnings) = recursive_compare(new_depth, k, s, r, ignored);
                    errors += new_errors;
                    warnings += new_warnings;
                } else {
                    if let Null = s {
                        // Ok to be missing a null
                    } else if ignored.contains(&&**k) {
                        warnings += 1;
                        println!(
                            "~{:width$}ignoring field {}: {}",
                            "",
                            k,
                            s,
                            width = new_depth
                        );
                    } else {
                        errors += 1;
                        println!("-{:width$}rust was missing", "", width = new_depth);
                        println!("+{:width$}{}: {}", "", k, s, width = new_depth);
                    }
                }
            }
            println!("{:width$} }}", "", width = depth);
        }
        (Array(s), Array(r)) => {
            if k == "modules" {
                // The module array is really a Set -- order doesn't matter. Analyze it as such.
                // "filename" is the key we generally use here, since it rarely conflicts.
                let convert_modules_to_map = |arr: &[serde_json::Value]| {
                    arr.iter()
                        .filter_map(|module| {
                            module
                                .get("filename")
                                .and_then(|v| v.as_str())
                                .map(|filename| (filename.to_string(), module.clone()))
                        })
                        .collect::<HashMap<std::string::String, serde_json::Value>>()
                };

                let s_modules = convert_modules_to_map(&**s);
                let r_modules = convert_modules_to_map(&**r);

                let mut all_keys = s_modules.keys().collect::<HashSet<_>>();
                all_keys.extend(r_modules.keys());

                let new_depth = depth + 2;
                println!("{:width$} {}: [", "", k, width = depth);
                for (i, &key) in all_keys.iter().enumerate() {
                    let s_val = s_modules.get(key).unwrap_or(&&Null);
                    let r_val = r_modules.get(key).unwrap_or(&&Null);

                    let (new_errors, new_warnings) =
                        recursive_compare(new_depth, &i.to_string(), s_val, r_val, ignored);

                    errors += new_errors;
                    warnings += new_warnings;
                }
                println!("{:width$} {}: ]", "", k, width = depth);
            } else {
                // The bulk of the refined analysis happens here, as we try to more intelligently
                // handle the array of frames in a backtrace. This is important because very small
                // differences can naively become massive differences. For instance if one backtrace
                // contains an extra frame, naive comparison would report that every single frame
                // after that point is different!
                let s_len = s.len();
                let r_len = r.len();
                let len = if s_len < r_len { s_len } else { r_len };

                println!("{:width$} {}: [", "", k, width = depth);
                let new_depth = depth + 2;

                let mut s_offset = 0;
                let mut r_offset = 0;

                // Iterate through all pairable values of the array (the equivalent of rust's
                // Iterator::zip(), but done manually so that we can advance only one of the
                // iterators when it would make a cleaner comparison).
                while s_offset < len && r_offset < len {
                    let s_val = &s[s_offset];
                    let r_val = &r[r_offset];

                    // Try to peek inside and see if these are both stack frames with different
                    // function names. If they are, try to peek ahead and see if an offset of
                    // a few frames will get everything back in sync.
                    if let (Object(s_obj), Object(r_obj)) = (s_val, r_val) {
                        if let (Some(String(s_func)), Some(String(r_func))) =
                            (s_obj.get("function"), r_obj.get("function"))
                        {
                            if s_func != r_func {
                                // Assume one of the values is "good" and scan ahead in the other for a match
                                let try_lookahead =
                                    |good: &serde_json::Map<
                                        std::string::String,
                                        serde_json::Value,
                                    >,
                                     bad_arr: &[serde_json::Value],
                                     current_idx: usize| {
                                        for i in 1..4 {
                                            if let Some(Object(bad)) = bad_arr.get(current_idx + i)
                                            {
                                                if let (
                                                    Some(String(good_func)),
                                                    Some(String(bad_func)),
                                                ) = (good.get("function"), bad.get("function"))
                                                {
                                                    if good_func == bad_func {
                                                        return Some(i);
                                                    }
                                                }
                                            }
                                        }
                                        None
                                    };

                                // If we do find skipping some frames results in a match, we only emit a warning
                                // if the rust frame had a better (lower) trust level. This hopefully allows us
                                // to focus on places where rust is doing something weird on equal or worse
                                // information. This will however supress situations where rust is failing
                                // to properly validate itself and e.g. accepts malformed results from cfi.
                                let (s_trust, r_trust) = trust_levels(
                                    s_obj.get("trust").unwrap(),
                                    r_obj.get("trust").unwrap(),
                                );
                                if let Some(r_skip) = try_lookahead(&s_obj, &r, r_offset) {
                                    // We found a match further along the rust array, print the frames we're
                                    // skipping more concisely and jump ahead in rust's stream.
                                    for i in 0..r_skip {
                                        let r_offset = r_offset + i;
                                        let r_val = &r[r_offset];
                                        if s_trust <= r_trust {
                                            errors += 1;
                                            println!(
                                                "-{:width$}rust had extra array value:",
                                                "",
                                                width = new_depth
                                            );
                                        } else {
                                            warnings += 1;
                                            println!("~{:width$}rust had extra array value (but rust has better trust):", "", width=new_depth);
                                        }
                                        recursive_print(new_depth, &r_offset.to_string(), r_val);
                                    }
                                    r_offset += r_skip;
                                    continue;
                                } else if let Some(s_skip) = try_lookahead(&r_obj, &s, s_offset) {
                                    // We found a match further along the socc array, print the frames we're
                                    // skipping more concisely and jump ahead in socc's stream.
                                    for i in 0..s_skip {
                                        let s_offset = s_offset + i;
                                        let s_val = &s[s_offset];

                                        if s_trust <= r_trust {
                                            errors += 1;
                                            println!(
                                                "-{:width$}socc had extra array value:",
                                                "",
                                                width = new_depth
                                            );
                                        } else {
                                            warnings += 1;
                                            println!("~{:width$}socc had extra array value (but rust has better trust):", "", width=new_depth);
                                        }
                                        recursive_print(new_depth, &s_offset.to_string(), s_val);
                                    }
                                    s_offset += s_skip;
                                    continue;
                                }
                            }
                        }
                    }

                    // If we get here then there wasn't any opportunity to more intelligently analyze this pair
                    // of array entries -- just recursively compare their individual fields instead.
                    let (new_errors, new_warnings) =
                        recursive_compare(new_depth, &s_offset.to_string(), s_val, r_val, ignored);
                    errors += new_errors;
                    warnings += new_warnings;

                    s_offset += 1;
                    r_offset += 1;
                }

                // We have now analyzed all the matching values, but one of the arrays might have
                // some extra trailing values, and we try to report those here.

                // Try to get the trust levels of the last entries we looked at. This way we
                // can make it only a warning if rust was going into these trailing values with a
                // better (lower) trust level. If it did, presumably these frames are either socc
                // hallucinating junk or rust producing richer information...... presumably...
                let mut last_s_trust = 99;
                let mut last_r_trust = 99;
                if s_offset > 0 && r_offset > 0 {
                    if let (Some(s_trust), Some(r_trust)) =
                        (s[s_offset - 1].get("trust"), r[r_offset - 1].get("trust"))
                    {
                        let trust = trust_levels(s_trust, r_trust);
                        last_s_trust = trust.0;
                        last_r_trust = trust.1;
                    }
                }

                // Display non-paired values
                for i in s_offset..s_len {
                    if last_s_trust <= last_r_trust {
                        errors += 1;
                        println!(
                            "-{:width$}rust was missing array value:",
                            "",
                            width = new_depth
                        );
                    } else {
                        warnings += 1;
                        println!(
                            "~{:width$}rust was missing array value (but rust has better trust):",
                            "",
                            width = new_depth
                        );
                    }
                    recursive_print(new_depth, &i.to_string(), &s[i]);
                }
                for i in r_offset..r_len {
                    if last_s_trust <= last_r_trust {
                        errors += 1;
                        println!(
                            "-{:width$}rust had extra array value:",
                            "",
                            width = new_depth
                        );
                    } else {
                        warnings += 1;
                        println!(
                            "~{:width$}rust had extra array value (but rust has better trust):",
                            "",
                            width = new_depth
                        );
                    }
                    recursive_print(new_depth, &i.to_string(), &r[i]);
                }
                println!(" {:width$}]", "", width = depth);
            }
        }
        (_, Null) => {
            if ignored.contains(k) {
                warnings += 1;
                println!("~{:width$}ignoring null rust val:", "", width = depth);
                recursive_print(depth, k, socc_val);
            } else {
                errors += 1;
                println!("-{:width$}rust val was null instead of:", "", width = depth);
                recursive_print(depth, k, socc_val);
            }
        }
        _ => {
            errors += 1;
            println!(
                "-{:width$}completely different types for {}:",
                "",
                k,
                width = depth
            );
            println!("+");
            recursive_print(depth + 2, k, socc_val);
            println!("-");
            recursive_print(depth + 2, k, rust_val);
        }
    }
    (errors, warnings)
}

fn recursive_print(depth: usize, k: &str, val: &serde_json::Value) {
    use serde_json::Value::*;

    match val {
        Bool(val) => {
            println!("{:width$} {}: {}", "", k, val, width = depth);
        }
        Number(val) => {
            println!("{:width$} {}: {}", "", k, val, width = depth);
        }
        String(val) => {
            println!("{:width$} {}: {}", "", k, val, width = depth);
        }
        Object(val) => {
            println!("{:width$} {}: {{", "", k, width = depth);
            for (k, v) in val {
                recursive_print(depth + 2, k, v);
            }
            println!("{:width$} }}", "", width = depth);
        }
        Array(val) => {
            println!("{:width$} {}: [", "", k, width = depth);
            for i in 0..val.len() {
                recursive_print(depth + 2, &i.to_string(), &val[i]);
            }
            println!("{:width$} ]", "", width = depth);
        }
        Null => {
            println!("{:width$} {}: null", "", k, width = depth);
        }
    }
}

async fn fetch(request: reqwest::RequestBuilder, path: &Path) -> Result<File> {
    let name = path.file_name().unwrap().to_str().unwrap();
    if let Ok(file) = File::open(path) {
        println!("Had cached {}", name);
        Ok(file)
    } else {
        println!("Downloading {}", name);
        let payload = request.send().await?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;

        let content = payload.bytes().await?;
        copy(&mut &*content, &mut file)?;
        println!("Downloaded!");
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}

fn parse_int(int: &str) -> Option<u64> {
    int.strip_prefix("0x")
        .and_then(|s| u64::from_str_radix(s, 16).ok())
}

fn trust_levels(socc_val: &serde_json::Value, rust_val: &serde_json::Value) -> (usize, usize) {
    use serde_json::Value::*;
    let trust_levels = &["context", "cfi", "cfi_scan", "frame_pointer", "scan"];
    if let (String(s_trust), String(r_trust)) = (socc_val, rust_val) {
        let s_trust_level = trust_levels.iter().position(|x| x == s_trust).unwrap_or(99);
        let r_trust_level = trust_levels.iter().position(|x| x == r_trust).unwrap_or(99);
        (s_trust_level, r_trust_level)
    } else {
        (99, 99)
    }
}

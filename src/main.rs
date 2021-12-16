use error_chain::error_chain;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{copy, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::{crate_version, App, AppSettings, Arg};
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
                .default_value("trace")
                .takes_value(true)
                .long_help(
                    "Set the level of verbosity for the local minidum-stackwalk (off, error, warn, info, debug, trace (default))",
                ),
        )
        .arg(
            Arg::with_name("ignore-field")
                .multiple(true)
                .number_of_values(1)
                .long("ignore-field")
                .takes_value(true)
                .long_help(
                    "Fields in the json output to ignore the value of during comparison.

This is additive to the default ignore list. If you wish to disable the defaults, use --no-default-ignores

The default ignores are:

deprecated fields:
  * frames_truncated
  * tiny_block_size
  * write_combine_size
  * largest_free_vm_block

redundant fields:
  * total_frames
  * frame_count
  * threads_index
  * frame

debugging fields:
  * missing_symbols
  * symbol_disk_cache_hit
  * symbol_url
  * loaded_symbols
  * symbol_fetch_time

A warning will still be emitted for ignored fields. This is useful for deprecated fields \
which you don't care about the value of, or fields which contain redundant data like
the length of an array.\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("skip-diff")
                .long("skip-diff")
                .long_help(
                    "Skip the diffing process (just download files and run minidump-stackwalk)"
                )
        )
        .arg(
            Arg::with_name("clean-cache")
                .long("clean-cache")
                .long_help("Delete all cached files before running.

This is good to run periodically for data privacy, and for testing 'cold' runs.
"
                )
        )
        .arg(
            Arg::with_name("no-symbols")
                .long("no-symbols")
                .long_help("Do not provide any symbols to minidump-stackwalk

Lets you test symbol-less output.
"
                )
        )
        .arg(
            Arg::with_name("bench")
                .long("bench")
                .takes_value(true)
                .long_help(
                    "Repeatedly run minidump-stackwalk, and aggregate the results.

The provided value is the number of iterations to run.

If --clean is provided, the symbols-cache will be deleted before every run \
(but other cached files will only be deleted once, at the start.)
"
                )
        )
        .arg(
            Arg::with_name("no-default-ignores")
                .long("no-default-ignores")
                .long_help(
                    "Disable the default list of --ignore-field.\n\n",
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
                .number_of_values(1)
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
you, don't worry about it, you're probably not doing something that will run afoul of it).\n\n\n",
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
you, don't worry about it, you're probably not doing something that will run afoul of it).\n\n\n",
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
            Arg::with_name("run-local")
                .long("run-local")
                .takes_value(true)
                .long_help(
                    "A path to a local rust-minidump/minidump-stackwalk checkout to build and run

`cargo run --release -- <args>` will be invoked in the given directory.\n\n\n",
                ),
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

See https://crash-stats.mozilla.org/api/tokens/ for details.\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("crash-id")
                .long("crash-id")
                .takes_value(true)
                .required(true)
                .long_help(
                    "The socorro crash id to analyze.\n\n",
                ),
        )
        .get_matches();

    let output_file = matches
        .value_of_os("output-file")
        .map(|os_str| Path::new(os_str).to_owned());

    let log_file = matches
        .value_of_os("log-file")
        .map(|os_str| Path::new(os_str).to_owned());

    let local_checkout = matches
        .value_of_os("run-local")
        .map(|os_str| Path::new(os_str).to_owned());

    let verbose = matches.value_of("verbose").unwrap();
    // Verbose configures the child minidump-stackwalk, this app
    // doesn't have significant logging.
    let verbosity = LevelFilter::Warn;

    let mut stdout;
    let mut output_f;
    let f: &mut dyn Write = if let Some(output_path) = &output_file {
        output_f = File::create(output_path).unwrap();
        &mut output_f
    } else {
        stdout = std::io::stdout();
        &mut stdout
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
        "frame",
        // execution debugging
        "missing_symbols",
        "symbol_disk_cache_hit",
        "symbol_url",
        "loaded_symbols",
        "symbol_fetch_time",
    ];

    let skip_diff = matches.is_present("skip-diff");
    let no_default_ignores = matches.is_present("no-default-ignores");
    let clean_cache = matches.is_present("clean-cache");
    let no_symbols = matches.is_present("no-symbols");

    let bench_iters = matches
        .value_of("bench")
        .unwrap_or("1")
        .parse::<u64>()
        .expect("bench argument wasn't an integer!");
    assert!(bench_iters > 0, "bench iterations must be at least 1!");

    let mut ignored_fields = HashSet::new();
    if !no_default_ignores {
        ignored_fields.extend(default_ignored_fields);
    }
    ignored_fields.extend(
        matches
            .values_of("ignore-field")
            .unwrap_or_default()
            .into_iter(),
    );

    let compare_field = matches.value_of("compare");

    /////////////////////////////////////////////////////////////
    /////////// ACTUAL EXECUTION STARTS HERE ////////////////////
    /////////////////////////////////////////////////////////////

    // Ensure the dump cache exists (and maybe clear it)
    if clean_cache {
        fs::remove_dir_all(&dump_cache)?;
    }
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

    fetch(f, minidump_req, &minidump).await?;

    // Download the json socorro has for the minidump
    let socc_output_req = reqwest::Client::new()
        .get("https://crash-stats.mozilla.org/api/ProcessedCrash/")
        .header("Auth-Token", api_token)
        .query(&[("crash_id", crash_id)]);
    let mut socc_output = dump_cache.join(&crash_id);
    socc_output.set_extension("json");

    let socc_json = fetch(f, socc_output_req, &socc_output).await?;
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
        let _extra_json = fetch(f, extra_json_req, &extra_json_path).await?;

        Some(extra_json_path)
    } else {
        // Assume --raw-json is a local path
        Some(PathBuf::from(raw_json_arg))
    };

    // Process the minidump with local minidump-stackwalk

    // Either grab whetever minidump-stackwalk is on PATH or build+run the
    // given local checkout.
    let mut command_temp;
    let mut command = if let Some(local_checkout) = local_checkout {
        writeln!(f)?;
        writeln!(f, "building local minidump-stackwalk...")?;

        let output = Command::new("cargo")
            .current_dir(local_checkout)
            .arg("build")
            .arg("--release")
            .arg("--message-format=json")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()?;

        let output_string = String::from_utf8_lossy(&output.stdout);
        let mut bin: String = String::new();
        for line in output_string.lines() {
            if line.starts_with("{") {
                let obj: serde_json::Value = serde_json::from_str(&line).unwrap();
                let is_artifact = obj
                    .get("reason")
                    .and_then(|i| i.as_str())
                    .unwrap_or_default()
                    == "compiler-artifact";
                let is_mdsw = obj
                    .get("package_id")
                    .and_then(|i| i.as_str())
                    .unwrap_or_default()
                    .starts_with("minidump-stackwalk");
                if is_artifact && is_mdsw {
                    bin = obj
                        .get("executable")
                        .and_then(|i| i.as_str())
                        .unwrap_or_default()
                        .to_string();
                }
            } else {
                writeln!(f, "{}", line)?;
            }
        }

        writeln!(f, "built {}", bin)?;
        command_temp = Command::new(bin);
        &mut command_temp
    } else {
        command_temp = Command::new("minidump-stackwalk");
        &mut command_temp
    };

    writeln!(f)?;
    writeln!(
        f,
        "running local minidump-stackwalk... ({} times)",
        bench_iters
    )?;

    if let Some(raw_json) = &raw_json {
        let mut arg = OsString::from("--raw-json=");
        arg.push(&raw_json);
        command = command.arg(arg);
    }

    if !no_symbols {
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

    {
        let mut arg = OsString::from("--verbose=");
        arg.push(&verbose);
        command = command.arg(arg);
    }

    {
        command = command.arg("--json");
    }

    command = command.arg(&minidump);

    // Different approaches to forwarding subprocess stdout based on
    // whether we're writing to a file or not.

    let mut status = None;
    let mut times = vec![];

    for i in 0..bench_iters {
        // Start by cleaning out the symbol cache (if needed)
        if clean_cache {
            fs::remove_dir_all(&symbols_cache)?;
        }

        if output_file.is_some() {
            let final_command = &mut *command.stdout(Stdio::piped()).stderr(Stdio::inherit());

            let start = Instant::now();
            let output = final_command.output()?;
            let end = Instant::now();

            writeln!(f, "{}", String::from_utf8_lossy(&output.stdout))?;
            status = Some(output.status);
            times.push(end - start);
        } else {
            let final_command = &mut *command;

            let start = Instant::now();
            status = final_command.status().ok();
            let end = Instant::now();

            times.push(end - start);
        };
        if status.unwrap().success() {
            writeln!(f, "done! ({}/{})", i + 1, bench_iters)?;
        } else {
            writeln!(f, "failed! ({}/{})", i + 1, bench_iters)?;
        }
    }

    if status.unwrap().success() {
        writeln!(f, "all done!")?;

        if !skip_diff {
            writeln!(f, "comparing json...")?;
            let local_json_file = File::open(&local_output)?;
            let local_json: serde_json::Value =
                serde_json::from_reader(BufReader::new(local_json_file)).unwrap();

            compare_crashes(f, compare_field, &ignored_fields, &socc_json, &local_json)?;
        }
    } else {
        if let Some(code) = status.unwrap().code() {
            writeln!(f, "failed! exit status: {}", code)?;
        } else {
            writeln!(f, "failed! (no exit status, terminated by signal?)")?;
        }
        writeln!(f, "dumping logs: ")?;

        let local_log_file = File::open(&local_logs)?;
        let mut logs = String::new();
        BufReader::new(local_log_file).read_to_string(&mut logs)?;
        writeln!(f, "{}", logs)?;
    }

    writeln!(f)?;

    fn write_time<F: Write>(mut f: F, time: Duration) -> std::result::Result<(), std::io::Error> {
        let secs = time.as_secs();
        let subsec_millis = time.subsec_millis();
        let mins = secs / 60;
        let submin_secs = secs - (mins * 60);

        writeln!(f, "{:02}m:{:02}s:{:04}ms", mins, submin_secs, subsec_millis)
    }

    if bench_iters == 1 {
        write!(f, "miniump-stackwalk runtime: ")?;
        write_time(&mut *f, times[0])?;
    } else {
        writeln!(f, "benchmark results (ms):")?;
        write!(f, "  ")?;
        let mut total_millis = 0;
        for time in &times {
            let millis = time.as_millis();
            write!(f, "{}, ", millis)?;
            total_millis += time.as_millis();
        }
        writeln!(f)?;

        // Sort to get ordered statistics
        times.sort();

        let average = Duration::from_millis((total_millis / (times.len() as u128)) as u64);
        let median = times[times.len() / 2];
        let min = *times.first().unwrap();
        let max = *times.last().unwrap();

        write!(f, "average runtime: ")?;
        write_time(&mut *f, average)?;
        write!(f, "median runtime: ")?;
        write_time(&mut *f, median)?;
        write!(f, "min runtime: ")?;
        write_time(&mut *f, min)?;
        write!(f, "max runtime: ")?;
        write_time(&mut *f, max)?;
    }
    writeln!(f)?;
    writeln!(f, "Output Files: ")?;
    writeln!(f, "  * (download) Minidump: {}", minidump.display())?;
    writeln!(
        f,
        "  * (download) Socorro Processed Crash: {}",
        socc_output.display()
    )?;
    if let Some(raw_json) = &raw_json {
        writeln!(f, "  * (download) Raw JSON: {}", raw_json.display())?;
    }
    writeln!(
        f,
        "  * Local minidump-stackwalk Output: {}",
        local_output.display()
    )?;
    writeln!(
        f,
        "  * Local minidump-stackwalk Logs: {}",
        local_logs.display()
    )?;

    Ok(())
}

fn compare_crashes(
    f: &mut dyn Write,
    compare_field: Option<&str>,
    ignored_fields: &HashSet<&str>,
    socc_json: &serde_json::Value,
    local_json: &serde_json::Value,
) -> std::result::Result<(), Error> {
    let (field, socc, local) = if let Some(field) = compare_field {
        // Only analyze this subfield
        (
            field,
            socc_json.get(field).unwrap(),
            local_json.get(field).unwrap(),
        )
    } else {
        // Analyze the whole output
        ("", socc_json, local_json)
    };

    writeln!(f, "")?;
    let (errors, warnings) = recursive_compare(f, 0, field, socc, local, ignored_fields)?;
    let status = if errors == 0 { "+" } else { "-" };
    writeln!(f, "")?;
    writeln!(
        f,
        "{} Total errors: {}, warnings: {}",
        status, errors, warnings
    )?;

    Ok(())
}

fn recursive_compare(
    f: &mut dyn Write,
    depth: usize,
    k: &str,
    socc_val: &serde_json::Value,
    local_val: &serde_json::Value,
    ignored: &HashSet<&str>,
) -> std::result::Result<(u64, u64), Error> {
    use serde_json::Value::*;

    let mut errors = 0;
    let mut warnings = 0;

    // These fields are either redundant or unimportant. Treat them being missing as only
    // a warning to allow us to focus on more significant problems.

    match (socc_val, local_val) {
        (Bool(s), Bool(r)) => {
            if s == r {
                writeln!(f, " {:width$}{}: {}", "", k, s, width = depth)?;
            } else if ignored.contains(&k) {
                warnings += 1;
                writeln!(
                    f,
                    "~{:width$}ignoring field {}: {}",
                    "",
                    k,
                    s,
                    width = depth
                )?;
            } else {
                errors += 1;
                writeln!(f, "-{:width$}did not match", "", width = depth)?;
                writeln!(f, "+{:width$}{}: {}", "", k, s, width = depth)?;
                writeln!(f, "-{:width$}{}: {}", "", k, r, width = depth)?;
            }
        }
        (Number(s), Number(r)) => {
            if s == r {
                writeln!(f, " {:width$}{}: {}", "", k, s, width = depth)?;
            } else if ignored.contains(&k) {
                warnings += 1;
                writeln!(
                    f,
                    "~{:width$}ignoring field {}: {}",
                    "",
                    k,
                    s,
                    width = depth
                )?;
            } else {
                errors += 1;
                writeln!(f, "-{:width$}did not match", "", width = depth)?;
                writeln!(f, "+{:width$}{}: {}", "", k, s, width = depth)?;
                writeln!(f, "-{:width$}{}: {}", "", k, r, width = depth)?;
            }
        }
        (String(s), String(r)) => {
            if let (Some(s), Some(r)) = (parse_int(s), parse_int(r)) {
                if s == r {
                    writeln!(f, " {:width$}{}: 0x{:08x}", "", k, s, width = depth)?;
                } else if ignored.contains(&k) {
                    writeln!(
                        f,
                        "~{:width$}ignoring field {}: 0x{:08x}",
                        "",
                        k,
                        s,
                        width = depth
                    )?;
                    warnings += 1;
                } else {
                    errors += 1;
                    writeln!(f, "-{:width$}did not match", "", width = depth)?;
                    writeln!(f, "+{:width$}{}: 0x{:08x}", "", k, s, width = depth)?;
                    writeln!(f, "-{:width$}{}: 0x{:08x}", "", k, r, width = depth)?;
                }
            } else {
                if s == r {
                    writeln!(f, " {:width$}{}: {}", "", k, s, width = depth)?;
                } else if ignored.contains(&k) {
                    writeln!(
                        f,
                        "~{:width$}ignoring field {}: {}",
                        "",
                        k,
                        s,
                        width = depth
                    )?;
                } else if k == "trust" {
                    let (s_trust, r_trust) = trust_levels(socc_val, local_val);
                    if r_trust < s_trust {
                        writeln!(
                            f,
                            "~{:width$}local had better trust ({} vs {})",
                            "",
                            s,
                            r,
                            width = depth
                        )?;
                        warnings += 1;
                    } else if s_trust < r_trust {
                        writeln!(
                            f,
                            "-{:width$}socc had better trust ({} vs {})",
                            "",
                            s,
                            r,
                            width = depth
                        )?;
                        errors += 1;
                    } else {
                        // Shouldn't be possible? I want to know if this happens.
                        unreachable!()
                    }
                } else {
                    errors += 1;
                    writeln!(f, "-{:width$}did not match", "", width = depth)?;
                    writeln!(f, "+{:width$}{}: {}", "", k, s, width = depth)?;
                    writeln!(f, "-{:width$}{}: {}", "", k, r, width = depth)?;
                }
            }
        }
        (Object(s), Object(r)) => {
            writeln!(f, "{:width$} {}: {{", "", k, width = depth)?;
            let new_depth = depth + 2;
            for (k, s) in s {
                if let Some(r) = r.get(k) {
                    let (new_errors, new_warnings) =
                        recursive_compare(f, new_depth, k, s, r, ignored)?;
                    errors += new_errors;
                    warnings += new_warnings;
                } else {
                    if let Null = s {
                        // Ok to be missing a null
                    } else if ignored.contains(&&**k) {
                        warnings += 1;
                        writeln!(
                            f,
                            "~{:width$}ignoring field {}: {}",
                            "",
                            k,
                            s,
                            width = new_depth
                        )?;
                    } else {
                        errors += 1;
                        writeln!(f, "-{:width$}local was missing", "", width = new_depth)?;
                        writeln!(f, "+{:width$}{}: {}", "", k, s, width = new_depth)?;
                    }
                }
            }
            writeln!(f, "{:width$} }}", "", width = depth)?;
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
                writeln!(f, "{:width$} {}: [", "", k, width = depth)?;
                for (i, &key) in all_keys.iter().enumerate() {
                    let s_val = s_modules.get(key).unwrap_or(&&Null);
                    let r_val = r_modules.get(key).unwrap_or(&&Null);

                    let (new_errors, new_warnings) =
                        recursive_compare(f, new_depth, &i.to_string(), s_val, r_val, ignored)?;

                    errors += new_errors;
                    warnings += new_warnings;
                }
                writeln!(f, "{:width$} ]", "", width = depth)?;
            } else {
                // The bulk of the refined analysis happens here, as we try to more intelligently
                // handle the array of frames in a backtrace. This is important because very small
                // differences can naively become massive differences. For instance if one backtrace
                // contains an extra frame, naive comparison would report that every single frame
                // after that point is different!
                let s_len = s.len();
                let r_len = r.len();
                let len = if s_len < r_len { s_len } else { r_len };

                writeln!(f, "{:width$} {}: [", "", k, width = depth)?;
                let new_depth = depth + 2;

                let mut s_offset = 0;
                let mut r_offset = 0;

                // Iterate through all pairable values of the array (the equivalent of local's
                // Iterator::zip(), but done manually so that we can advance only one of the
                // iterators when it would make a cleaner comparison).
                while s_offset < len && r_offset < len {
                    let s_val = &s[s_offset];
                    let r_val = &r[r_offset];

                    let mut are_different_frames = false;
                    // Try to peek inside and see if these are both stack frames with different
                    // function names. If they are, try to peek ahead and see if an offset of
                    // a few frames will get everything back in sync.
                    if let (Object(s_obj), Object(r_obj)) = (s_val, r_val) {
                        if let (Some(String(s_func)), Some(String(r_func))) =
                            (s_obj.get("offset"), r_obj.get("offset"))
                        {
                            if parse_int(s_func) != parse_int(r_func) {
                                are_different_frames = true;
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
                                                ) = (good.get("offset"), bad.get("offset"))
                                                {
                                                    if parse_int(good_func) == parse_int(bad_func) {
                                                        return Some(i);
                                                    }
                                                }
                                            }
                                        }
                                        None
                                    };

                                // If we do find skipping some frames results in a match, we only emit a warning
                                // if the local frame had a better (lower) trust level. This hopefully allows us
                                // to focus on places where local is doing something weird on equal or worse
                                // information. This will however supress situations where local is failing
                                // to properly validate itself and e.g. accepts malformed results from cfi.
                                let (s_trust, r_trust) = trust_levels(
                                    s_obj.get("trust").unwrap(),
                                    r_obj.get("trust").unwrap(),
                                );
                                if let Some(r_skip) = try_lookahead(&s_obj, &r, r_offset) {
                                    // We found a match further along the local array, print the frames we're
                                    // skipping more concisely and jump ahead in local's stream.
                                    for i in 0..r_skip {
                                        let r_offset = r_offset + i;
                                        let r_val = &r[r_offset];
                                        if s_trust <= r_trust {
                                            errors += 1;
                                            writeln!(
                                                f,
                                                "-{:width$}local had extra array value:",
                                                "",
                                                width = new_depth
                                            )?;
                                        } else {
                                            warnings += 1;
                                            writeln!(f, "~{:width$}local had extra array value (but local has better trust):", "", width=new_depth)?;
                                        }
                                        recursive_print(
                                            f,
                                            new_depth,
                                            &r_offset.to_string(),
                                            r_val,
                                        )?;
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
                                            writeln!(
                                                f,
                                                "-{:width$}socc had extra array value:",
                                                "",
                                                width = new_depth
                                            )?;
                                        } else {
                                            warnings += 1;
                                            writeln!(f, "~{:width$}socc had extra array value (but local has better trust):", "", width=new_depth)?;
                                        }
                                        recursive_print(
                                            f,
                                            new_depth,
                                            &s_offset.to_string(),
                                            s_val,
                                        )?;
                                    }
                                    s_offset += s_skip;
                                    continue;
                                }
                            }
                        }
                    }

                    if are_different_frames {
                        // we couldn't do any correcting by assuming an extra/missing entry in the array,
                        // but we do know these are stack frames, with different function names. If this
                        // happens, basically every value will be different, so only report one error
                        // for simplicity.
                        writeln!(
                            f,
                            "-{:width$}stack frames were completely different",
                            "",
                            width = new_depth
                        )?;
                        recursive_print(f, new_depth, &s_offset.to_string(), s_val)?;
                        recursive_print(f, new_depth, &s_offset.to_string(), r_val)?;
                        errors += 1;
                    } else {
                        // If we get here then there wasn't any opportunity to more intelligently analyze this pair
                        // of array entries -- just recursively compare their individual fields instead.
                        let (new_errors, new_warnings) = recursive_compare(
                            f,
                            new_depth,
                            &s_offset.to_string(),
                            s_val,
                            r_val,
                            ignored,
                        )?;
                        errors += new_errors;
                        warnings += new_warnings;
                    }
                    s_offset += 1;
                    r_offset += 1;
                }

                // We have now analyzed all the matching values, but one of the arrays might have
                // some extra trailing values, and we try to report those here.

                // Try to get the trust levels of the last entries we looked at. This way we
                // can make it only a warning if local was going into these trailing values with a
                // better (lower) trust level. If it did, presumably these frames are either socc
                // hallucinating junk or local producing richer information...... presumably...
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
                        writeln!(
                            f,
                            "-{:width$}local was missing array value:",
                            "",
                            width = new_depth
                        )?;
                    } else {
                        warnings += 1;
                        writeln!(
                            f,
                            "~{:width$}local was missing array value (but local has better trust):",
                            "",
                            width = new_depth
                        )?;
                    }
                    recursive_print(f, new_depth, &i.to_string(), &s[i])?;
                }
                for i in r_offset..r_len {
                    if last_s_trust <= last_r_trust {
                        errors += 1;
                        writeln!(
                            f,
                            "-{:width$}local had extra array value:",
                            "",
                            width = new_depth
                        )?;
                    } else {
                        warnings += 1;
                        writeln!(
                            f,
                            "~{:width$}local had extra array value (but local has better trust):",
                            "",
                            width = new_depth
                        )?;
                    }
                    recursive_print(f, new_depth, &i.to_string(), &r[i])?;
                }
                writeln!(f, " {:width$}]", "", width = depth)?;
            }
        }
        (Null, Null) => {
            writeln!(f, " {:width$}{}: null", "", k, width = depth)?;
        }
        (_, Null) => {
            if socc_val.as_str() == Some("") {
                // Socorro sometimes has blanks for nulls, consider them equal
                writeln!(f, " {:width$}{}: null", "", k, width = depth)?;
            } else {
                if ignored.contains(k) {
                    warnings += 1;
                    writeln!(f, "~{:width$}ignoring null local val:", "", width = depth)?;
                    recursive_print(f, depth, k, socc_val)?;
                } else {
                    errors += 1;
                    writeln!(
                        f,
                        "-{:width$}local val was null instead of:",
                        "",
                        width = depth
                    )?;
                    recursive_print(f, depth, k, socc_val)?;
                }
            }
        }
        _ => {
            errors += 1;
            writeln!(
                f,
                "-{:width$}completely different types for {}:",
                "",
                k,
                width = depth
            )?;
            writeln!(f, "+")?;
            recursive_print(f, depth + 2, k, socc_val)?;
            writeln!(f, "-")?;
            recursive_print(f, depth + 2, k, local_val)?;
        }
    }
    Ok((errors, warnings))
}

fn recursive_print(
    f: &mut dyn Write,
    depth: usize,
    k: &str,
    val: &serde_json::Value,
) -> std::result::Result<(), Error> {
    use serde_json::Value::*;

    match val {
        Bool(val) => {
            writeln!(f, "{:width$} {}: {}", "", k, val, width = depth)?;
        }
        Number(val) => {
            writeln!(f, "{:width$} {}: {}", "", k, val, width = depth)?;
        }
        String(val) => {
            writeln!(f, "{:width$} {}: {}", "", k, val, width = depth)?;
        }
        Object(val) => {
            writeln!(f, "{:width$} {}: {{", "", k, width = depth)?;
            for (k, v) in val {
                recursive_print(f, depth + 2, k, v)?;
            }
            writeln!(f, "{:width$} }}", "", width = depth)?;
        }
        Array(val) => {
            writeln!(f, "{:width$} {}: [", "", k, width = depth)?;
            for i in 0..val.len() {
                recursive_print(f, depth + 2, &i.to_string(), &val[i])?;
            }
            writeln!(f, "{:width$} ]", "", width = depth)?;
        }
        Null => {
            writeln!(f, "{:width$} {}: null", "", k, width = depth)?;
        }
    }
    Ok(())
}

async fn fetch(f: &mut dyn Write, request: reqwest::RequestBuilder, path: &Path) -> Result<File> {
    let name = path.file_name().unwrap().to_str().unwrap();
    if let Ok(file) = File::open(path) {
        writeln!(f, "Had cached {}", name)?;
        Ok(file)
    } else {
        writeln!(f, "Downloading {}", name)?;
        let payload = request.send().await?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;

        let content = payload.bytes().await?;
        copy(&mut &*content, &mut file)?;
        writeln!(f, "Downloaded!")?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}

fn parse_int(int: &str) -> Option<u64> {
    int.strip_prefix("0x")
        .and_then(|s| u64::from_str_radix(s, 16).ok())
}

fn trust_levels(socc_val: &serde_json::Value, local_val: &serde_json::Value) -> (usize, usize) {
    use serde_json::Value::*;
    let trust_levels = &["context", "cfi", "cfi_scan", "frame_pointer", "scan"];
    if let (String(s_trust), String(r_trust)) = (socc_val, local_val) {
        let s_trust_level = trust_levels.iter().position(|x| x == s_trust).unwrap_or(99);
        let r_trust_level = trust_levels.iter().position(|x| x == r_trust).unwrap_or(99);
        (s_trust_level, r_trust_level)
    } else {
        (99, 99)
    }
}

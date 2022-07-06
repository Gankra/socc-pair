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
use wait4::Wait4;

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
  * stackwalk_version

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
            Arg::with_name("cyborg")
                .long("cyborg")
                .long_help(
                    "Produce both --human and --json output for minidump-stackwalk"
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
            Arg::with_name("mock-server")
                .long("mock-server")
                .long_help("Run a local symbol-server to test symbol downloading.

NOTE: This partially implies the semantics of --clean-cache! Details below.

This is recommended for benchmarking the symbol download path more reliably
(and without downloading terabytes of symbol files).

This will introduce an extra (discarded) execution of minidump-stackwalk at the \
start. The extra execution is run without the mock server to ensure \
we have all of the symbols our symbol server needs from the *real* servers \
stored in the symbols-cache. If those symbols are already in the symbols-cache, \
then they won't be re-downloaded during this process.

We then copy the symbols-cache to another directory (see --mock-server-cache) \
and run a simple static file server for that directory on localhost:3142. \
At this point, the normal iterations of minidump-stackwalk will begin, but \
with --symbols-url set to 'localhost:3142'.

Before *every* iteration of minidump-stackwalk (see --bench), we will delete \
the symbols-cache as if --clean-cache was passed. This is the only way to \
actually make minidump-stackwalk query our server, while still testing all \
the code the populates the cache.

The mock-server-cache directory won't be deleted at the end of execution, so you \
can inspect its contents if you think something weird has happened.

The mock-server-cache directory *will* be deleted and recreated at the \
*start* of socc-pair's execution, just to be safe/consistent. This \
*will not* result in all the symbol files needing to be redownloaded from the \
'real' file-server if you repeatedly use --mock-server, because the symbols-cache \
will contain all the symbol files used at the end of each execution.

That said, any files that were in the symbol cache but not needed for the current \
minidump *will* be deleted as a side-effect of this process.\n\n\n"
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

If the value is greater than 1, then all analysis (diffing) and output files
will be based on the *last* execution.

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
            Arg::with_name("evil-json")
                .long("evil-json")
                .default_value("default")
                .takes_value(true)
                .long_help(
                    "An input JSON file with the extra information.

Possible values:
* 'default' - 'socorro' if using socorro (--crash-id), 'none' otherwise
* 'none' - Do not use an evil-json
* 'socorro' - Get the 'raw' JSON from socorro 
  (API token may require 'View Personal Identifiable Information') 
* <anything else> - assumed to be a path to a local evil-json file

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
            Arg::with_name("mock-server-cache")
                .long("mock-server-cache")
                .takes_value(true)
                .long_help(
                    "Where to store the files for the mock symbol server.

Defaults to std::env::temp_dir()/socc-pair/server/

When you use --mock-server we need to copy symbol files out of \
rust-minidump's cache to our own directory that we can run a \
simple static file server on -- this is that directory.\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("mock-server-port")
                .long("mock-server-port")
                .takes_value(true)
                .default_value("3142")
                .long_help(
                    "The localhost port --mock-server should use.\n\n\n",
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
/*
We basically don't use stderr, only Cargo output goes there,
so this option is a confusing trap.
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .takes_value(true)
                .help("Where to write logs to (if unspecified, stderr is used)"),
        )
*/
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
                .long_help(
                    "A socorro api token to use for getting minidumps

Required permissions:

* 'View Raw Dumps' (hard required)
* 'View Personal Identifiable Information' (to read some entries in raw-json/evil-json)

See https://crash-stats.mozilla.org/api/tokens/ for details.\n\n\n",
                ),
        )
        .arg(
            Arg::with_name("minidump")
                .long("minidump")
                .takes_value(true)
                .long_help(
                    "A local minidump to analyze (instead of using --api-token and --crash-id) \n\n\n",
                ),
        )
        .arg(
            Arg::with_name("crash-id")
                .long("crash-id")
                .takes_value(true)
                .long_help(
                    "The socorro crash id to analyze.\n\n",
                ),
        )
        .get_matches();

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    /////////////////// PARSE CLI FLAGS /////////////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    let output_file = matches
        .value_of_os("output-file")
        .map(|os_str| Path::new(os_str).to_owned());

    let log_file = matches
        .value_of_os("log-file")
        .map(|os_str| Path::new(os_str).to_owned());

    let local_checkout = matches
        .value_of_os("run-local")
        .map(|os_str| Path::new(os_str).to_owned());

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

    let bench_iters = matches
        .value_of("bench")
        .unwrap_or("0")
        .parse::<u64>()
        .expect("bench argument wasn't an integer!");

    // Remember if we're benchmarking
    let benching = bench_iters > 0;
    // But ensure there's at least one iteration
    let bench_iters = u64::max(bench_iters, 1);

    let mut verbose = matches.value_of("verbose").unwrap();

    if benching {
        writeln!(
            f,
            "\nNOTE: setting minidump-stackwalk --verbose to 'error' for benchmarking\n"
        )?;
        verbose = "error";
    }

    let temp_dir = std::env::temp_dir();
    let socc_tmp = temp_dir.join("socc-pair");
    let install_tmp = socc_tmp.join("install");

    // Default to env::temp_dir()/socc-pair/dumps
    let dump_cache = matches
        .value_of_os("socorro-cache")
        .map(|os_str| Path::new(os_str).to_owned())
        .unwrap_or_else(|| socc_tmp.join("dumps"));

    // Default to env::temp_dir()/socc-pair/server
    let mock_server_cache = matches
        .value_of_os("mock-server-cache")
        .map(|os_str| Path::new(os_str).to_owned())
        .unwrap_or_else(|| socc_tmp.join("server"));

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

    let evil_json_arg = matches.value_of_os("evil-json").expect("Missing evil json");

    let api_token = matches.value_of("api-token");
    let crash_id = matches.value_of("crash-id");
    let local_minidump = matches.value_of("minidump").map(|path| PathBuf::from(path));

    let using_socorro = api_token.is_some() && crash_id.is_some();
    let trying_to_use_socorro = api_token.is_some() || crash_id.is_some();
    let using_local_minidump = local_minidump.is_some();

    if using_local_minidump && trying_to_use_socorro {
        let err = "--minidump is incompatible with --api-token and --crash-id".to_string();
        eprintln!("ERROR: {}\n", err);
        return Err(err.into());
    }

    if !using_socorro && trying_to_use_socorro {
        let err = "--api-token and --crash-id must be used together".to_string();
        eprintln!("ERROR: {}\n", err);
        return Err(err.into());
    }

    let _local_minidump_str;
    let crash_id = if let Some(crash_id) = crash_id {
        // using socorro
        crash_id
    } else {
        // using local
        _local_minidump_str = local_minidump
            .as_ref()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        &_local_minidump_str
    };

    let evil_json_arg = if evil_json_arg == OsStr::new("default") {
        if using_local_minidump {
            OsStr::new("none")
        } else {
            OsStr::new("socorro")
        }
    } else {
        evil_json_arg
    };

    if !using_socorro && evil_json_arg == OsStr::new("socorro") {
        let err = "--evil-json=socorro requires socorro (--crash-id)".to_string();
        eprintln!("ERROR: {}\n", err);
        return Err(err.into());
    }

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
        "stackwalk_version",
    ];

    let skip_diff = matches.is_present("skip-diff");
    let no_default_ignores = matches.is_present("no-default-ignores");
    let clean_cache = matches.is_present("clean-cache");
    let mock_server = matches.is_present("mock-server");
    let no_symbols = matches.is_present("no-symbols");
    let cyborg = matches.is_present("cyborg");
    let mock_server_port = matches
        .value_of("mock-server-port")
        .expect("missing mock server port");
    let mock_server_url = format!("http://localhost:{}", mock_server_port);

    assert!(
        !mock_server || !no_symbols,
        "Are you mocking me??? (--mock-server and --no-symbols can't both be set)"
    );

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

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    ///////////////// GET FILES FROM SOCORRO ////////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    // Always purge the mock server cache to be safe/consistent.

    if mock_server_cache.exists() {
        fs::remove_dir_all(&mock_server_cache)?;
    }
    fs::create_dir_all(&mock_server_cache)?;

    // Ensure the dump cache exists (and maybe clear it)
    if clean_cache && dump_cache.exists() {
        fs::remove_dir_all(&dump_cache)?;
    }
    fs::create_dir_all(&dump_cache)?;

    // output paths to report:
    // * minidump (the minidump to analyze)
    // * socc_output (socorro processed crash)
    // * evil_json ("extra" json file AKA evil-json)
    // * local_json_output (local minidump-stackwalk --json output)
    // * local_human_output (local minidump-stackwalk --human output)
    // * local_logs (local minidump-stackwalk log output)

    let mut local_json_output = dump_cache.join(&crash_id);
    local_json_output.set_extension("local.json");

    let mut local_human_output = dump_cache.join(&crash_id);
    local_human_output.set_extension("local.txt");

    let mut local_logs = dump_cache.join(&crash_id);
    local_logs.set_extension("log.txt");

    let minidump = if let Some(api_token) = &api_token {
        let mut minidump_dest = dump_cache.join(&crash_id);
        minidump_dest.set_extension("dmp");

        // Download the minidump
        let minidump_req = reqwest::Client::new()
            .get("https://crash-stats.mozilla.org/api/RawCrash/")
            .header("Auth-Token", *api_token)
            .query(&[
                ("crash_id", crash_id),
                ("format", "raw"),
                ("name", "upload_file_minidump"),
            ]);

        fetch(f, minidump_req, &minidump_dest).await?;

        minidump_dest
    } else {
        local_minidump.unwrap()
    };

    let mut socc_output = None;
    let mut socc_json = None;
    let tmp_socc_json2: serde_json::Value;

    if let Some(api_token) = &api_token {
        // Download the json socorro has for the minidump
        let socc_output_req = reqwest::Client::new()
            .get("https://crash-stats.mozilla.org/api/ProcessedCrash/")
            .header("Auth-Token", *api_token)
            .query(&[("crash_id", crash_id)]);
        let mut tmp_socc_output = dump_cache.join(&crash_id);
        tmp_socc_output.set_extension("json");

        if !skip_diff {
            let tmp_socc_json1 = fetch(f, socc_output_req, &tmp_socc_output).await?;
            tmp_socc_json2 = serde_json::from_reader(BufReader::new(tmp_socc_json1)).unwrap();

            socc_json = tmp_socc_json2.get("json_dump");
        }
        socc_output = Some(tmp_socc_output);
    }

    // Get the "raw" json file with things like certificate info
    let evil_json = if evil_json_arg == OsStr::new("none") {
        // Don't use raw json
        None
    } else if evil_json_arg == OsStr::new("socorro") {
        // Download the raw json from socorro
        let extra_json_req = reqwest::Client::new()
            .get("https://crash-stats.mozilla.org/api/RawCrash/")
            .header("Auth-Token", api_token.unwrap())
            .query(&[("crash_id", crash_id)]);
        let mut extra_json_path = dump_cache.join(&crash_id);
        extra_json_path.set_extension("evil.json");

        // Just need it on disk for rust-minidump, don't actually need the value here.
        let _extra_json = fetch(f, extra_json_req, &extra_json_path).await?;

        Some(extra_json_path)
    } else {
        // Assume --raw-json is a local path
        Some(PathBuf::from(evil_json_arg))
    };

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    /////////// GET THE LOCAL MINIDUMP-STACKWALK ////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    // Either grab whetever minidump-stackwalk is on PATH or build+run the
    // given local checkout.
    let minidump_stackwalk_bin = if let Some(local_checkout) = local_checkout {
        // Build it!
        writeln!(f, "\nbuilding local minidump-stackwalk...")?;

        let output = Command::new("cargo")
            .current_dir(local_checkout)
            .arg("build")
            .arg("--release")
            .arg("--message-format=json")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()?;

        let output_string = String::from_utf8_lossy(&output.stdout);
        let mut bin: PathBuf = PathBuf::new();
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
                        .to_string()
                        .into();
                }
            } else {
                writeln!(f, "{}", line)?;
            }
        }

        writeln!(f, "built {:?}", bin)?;
        bin
    } else {
        install_bin(f, &install_tmp, "minidump-stackwalk", ">= 0.9.6")?
    };

    let mdsw_version = {
        let output = Command::new(&minidump_stackwalk_bin)
            .arg("-V")
            .output()?
            .stdout;
        let output_str = std::str::from_utf8(&output)
            .expect("minidump-stackwalk -V wasn't utf8??")
            .trim();
        let (name, version) = output_str
            .split_once(' ')
            .expect("Couldn't parse minidump-stackwalk version");
        assert_eq!(name, "minidump-stackwalk");
        semver::Version::parse(version).expect("Could not parse minidump-stackwalk version")
    };

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    /////////// CONFIGURE MINIDUMP-STACKWALK ////////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    let mut command_temp = Command::new(&minidump_stackwalk_bin);
    let mut command = &mut command_temp;

    if let Some(evil_json) = &evil_json {
        let mut arg = if mdsw_version >= semver::Version::parse("0.10.0").unwrap() {
            OsString::from("--evil-json=")
        } else {
            OsString::from("--raw-json=")
        };
        arg.push(&evil_json);
        command = command.arg(arg);
    }

    if !no_symbols {
        // The mock server needs a special run of minidump-stackwalk that uses
        // the real symbol server to get its symbols, but we don't actually need
        // to configure minidump-stackwalk differently for this run -- we can
        // just make the mock server its "first choice", which it will cascade
        // over during the run when the server doesn't exist yet.
        //
        // This has the mild side-effect that it will query *both* the mock
        // server *and* the real server for any symbols that are missing from
        // the real server. Hopefully that's not significant?
        //
        // TODO: maybe this is a bad idea -- the timeout is *really* long.
        if mock_server {
            let mut arg = OsString::from("--symbols-url=");
            arg.push(&mock_server_url);
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
    }

    if cyborg {
        let mut arg = OsString::from("--cyborg=");
        arg.push(&local_json_output);
        command = command.arg(arg);

        let mut arg = OsString::from("--output-file=");
        arg.push(&local_human_output);
        command = command.arg(arg);
    } else {
        command = command.arg("--json");

        let mut arg = OsString::from("--output-file=");
        arg.push(&local_json_output);
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
        command = command.arg("--pretty");
    }

    command = command.arg(&minidump);

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    ///////////////// SETUP THE MOCK SERVER /////////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    struct ChildGuard {
        child: std::process::Child,
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            self.child.kill().unwrap()
        }
    }
    let mut _static_file_server = None;

    if mock_server {
        {
            writeln!(
                f,
                "Setting up static file server (sfz) at {}",
                mock_server_url
            )?;

            // We use the binary "sfz" to server our files.
            let static_file_server_bin = install_bin(f, &install_tmp, "sfz", "=0.6.2")?;

            // Now finally launch the server, and set up a guard that will
            // kill it when this process exits.
            let child = Command::new(static_file_server_bin)
                .arg("--port")
                .arg(mock_server_port)
                .arg(&mock_server_cache)
                .spawn()
                .expect("could not spawn static file server");
            _static_file_server = Some(ChildGuard { child });
        }

        writeln!(
            f,
            "\nrunning local minidump-stackwalk to populate mock-server's symbols...",
        )?;
        if output_file.is_some() {
            eprintln!("\nrunning local minidump-stackwalk to populate mock-server's symbols...");
        }

        // Run minidump-stackwalk like normal to populate its symbols-cache
        if clean_cache && symbols_cache.exists() {
            fs::remove_dir_all(&symbols_cache)?;
        }
        fs::create_dir_all(&symbols_cache)?;

        let final_command = &mut *command;
        let wait4 = final_command.spawn()?.wait4()?;

        if wait4.status.success() {
            writeln!(f, "done!")?;

            // Copy all files from symbols_cache to mock_server_cache (and recreate an empty symbols cache)
            fs::remove_dir_all(&mock_server_cache)?;
            fs::create_dir_all(
                mock_server_cache
                    .parent()
                    .expect("why is the mock server cache the root of your file system??"),
            )?;
            fs::rename(&symbols_cache, &mock_server_cache)?;
            fs::create_dir_all(&symbols_cache)?;
        } else {
            writeln!(f, "failed! aborting.")?;
            //return Err(());
        }
    }

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    ///////////////// RUN MINIDUMP-STACKWALK ////////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    writeln!(
        f,
        "\nrunning local minidump-stackwalk... ({} times)",
        bench_iters
    )?;
    if output_file.is_some() {
        eprintln!(
            "\nrunning local minidump-stackwalk... ({} times)",
            bench_iters
        );
    }

    let mut statuses = vec![];
    let mut times = vec![];
    let mut mems = vec![];

    for i in 1..=bench_iters {
        // Start by cleaning out the symbol cache (if needed)
        if (clean_cache || mock_server) && symbols_cache.exists() {
            fs::remove_dir_all(&symbols_cache)?;
        }
        // But also make sure the parent directories exist!
        fs::create_dir_all(&symbols_cache)?;

        // Reborrow the command so we can rerun it multiple times.
        let final_command = &mut *command;

        // Spawn minidump-stackwalk wait for the process to end.
        let start = Instant::now();
        let wait4 = final_command.spawn()?.wait4()?;
        let end = Instant::now();

        // Record statistics for the run
        times.push(end - start);
        mems.push(wait4.rusage.maxrss);
        statuses.push(wait4.status);

        // Report status
        if wait4.status.success() {
            writeln!(f, "done! ({}/{})", i, bench_iters)?;
        } else if let Some(code) = wait4.status.code() {
            writeln!(f, "failed! ({}/{}) exit status: {}", i, bench_iters, code)?;
        } else {
            writeln!(
                f,
                "failed! ({}/{}) (no exit status, terminated by signal?)",
                i, bench_iters
            )?;
        }
    }

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    /////////////////// DIFF THE JSON OUTPUT ////////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    if statuses.iter().all(|s| s.success()) {
        writeln!(f, "all done!\n")?;

        if let Some(socc_json) = &socc_json {
            // Note, only the results of the last run will be used
            // (we assume they're all equivalent).
            writeln!(f, "comparing json...")?;
            let local_json_file = File::open(&local_json_output)?;
            let local_json: serde_json::Value =
                serde_json::from_reader(BufReader::new(local_json_file)).unwrap();

            compare_crashes(f, compare_field, &ignored_fields, &socc_json, &local_json)?;
        }
    } else {
        writeln!(f, "some executions failed!")?;
        writeln!(f, "dumping logs: ")?;

        let local_log_file = File::open(&local_logs)?;
        let mut logs = String::new();
        BufReader::new(local_log_file).read_to_string(&mut logs)?;
        writeln!(f, "{}", logs)?;
    }

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    ////////////////////// PRINT STATISTICS /////////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    fn write_time<F: Write>(mut f: F, time: Duration) -> std::result::Result<(), std::io::Error> {
        let secs = time.as_secs();
        let subsec_millis = time.subsec_millis();
        let millis = time.as_millis();
        let mins = secs / 60;
        let submin_secs = secs - (mins * 60);

        writeln!(
            f,
            "{:02}m:{:02}s:{:03}ms ({}ms)",
            mins, submin_secs, subsec_millis, millis
        )
    }

    fn write_mem<F: Write>(mut f: F, mem: u64) -> std::result::Result<(), std::io::Error> {
        let mb = mem / (1024 * 1024);

        writeln!(f, "{}MB ({} bytes)", mb, mem)
    }

    if bench_iters == 1 {
        if !times.is_empty() {
            write!(f, "miniump-stackwalk runtime: ")?;
            write_time(&mut *f, times[0])?;
        }
        if !mems.is_empty() {
            write!(f, "miniump-stackwalk max memory (rss): ")?;
            write_mem(&mut *f, mems[0])?;
        }
    } else {
        if !times.is_empty() {
            writeln!(f)?;
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

        if !mems.is_empty() {
            writeln!(f)?;
            writeln!(f, "max memory (rss) results (bytes):")?;
            write!(f, "  ")?;
            let mut total_mem: u128 = 0;
            for &mem in &mems {
                write!(f, "{}, ", mem)?;
                total_mem += mem as u128;
            }
            writeln!(f)?;

            // Sort to get ordered statistics
            mems.sort();

            let average = (total_mem / (mems.len() as u128)) as u64;
            let median = mems[mems.len() / 2];
            let min = *mems.first().unwrap();
            let max = *mems.last().unwrap();

            write!(f, "average max-memory: ")?;
            write_mem(&mut *f, average)?;
            write!(f, "median max-memory: ")?;
            write_mem(&mut *f, median)?;
            write!(f, "min max-memory: ")?;
            write_mem(&mut *f, min)?;
            write!(f, "max max-memory: ")?;
            write_mem(&mut *f, max)?;
        }
    }

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /////////////////////////////////////////////////////////////
    ////////////////// PRINT ALL SAVED FILES ////////////////////
    /////////////////////////////////////////////////////////////
    //
    //
    //
    //
    //
    //
    //
    //
    //

    writeln!(f)?;
    writeln!(f, "Output Files: ")?;
    if using_local_minidump {
        writeln!(f, "  * Minidump: {}", minidump.display())?;
    } else {
        writeln!(f, "  * (download) Minidump: {}", minidump.display())?;
    }
    if let Some(socc_output) = &socc_output {
        writeln!(
            f,
            "  * (download) Socorro Processed Crash: {}",
            socc_output.display()
        )?;
    }
    if let Some(evil_json) = &evil_json {
        writeln!(f, "  * (download) Evil JSON: {}", evil_json.display())?;
    }
    writeln!(
        f,
        "  * Local minidump-stackwalk --json Output: {}",
        local_json_output.display()
    )?;
    if cyborg {
        writeln!(
            f,
            "  * Local minidump-stackwalk --human Output: {}",
            local_human_output.display()
        )?;
    }
    writeln!(
        f,
        "  * Local minidump-stackwalk Logs: {}",
        local_logs.display()
    )?;

    writeln!(f, " ")?;

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

/// Build a binary via `cargo install` and return a path to it.
///
/// If running a local checkout of socc-pair, binaries will be
/// installed to target/bin-deps/bin/. Otherwise they will be
/// installed to the socc-pair temp dir.
fn install_bin(
    f: &mut dyn Write,
    install_tmp: &Path,
    bin_name: &str,
    version: &str,
) -> Result<PathBuf> {
    // First check if there's a `target/` dir. If there is, then assume
    // we're running socc-pair via `cargo run` and `install` into `target/`.
    // Otherwise, `cargo install` globally.
    let target_path = Path::new("target/");
    let install_root = if target_path.is_dir() {
        Path::new(&"target/bin-deps/")
    } else {
        install_tmp
    };
    // Build the binary
    let build_status = Command::new("cargo")
        .arg("install")
        .arg("--root")
        .arg(install_root)
        .arg("--version")
        .arg(version)
        .arg(bin_name)
        .status()?;

    if !build_status.success() {
        let err = format!(
            "Could not build {} - build failed {}",
            bin_name, build_status
        );
        writeln!(f, "{}", err)?;
        return Err(err.into());
    }

    // Then find out the platform-specific binary name by parsing `cargo install --list`
    let list_command = Command::new("cargo")
        .arg("install")
        .arg("--root")
        .arg(install_root)
        .arg("--list")
        .output()?;

    if !list_command.status.success() {
        let err = format!(
            "Could not build {} - binary listing failed {}",
            bin_name, list_command.status
        );
        return Err(err.into());
    }

    // Format is a simple line-separated listing of all installed binaries
    let listing = String::from_utf8(list_command.stdout).unwrap();
    let mut lines = listing.lines();
    let true_bin_name;
    let search_string = format!("{} v", bin_name);
    loop {
        if let Some(line) = lines.next() {
            // looking for a line like "sfz v0.1.6"
            if line.starts_with(&search_string) {
                // binary name will be on the next line
                true_bin_name = lines.next().unwrap().trim();
                break;
            }
        } else {
            let err = format!(
                "Could not build {} - binary listing did not contain it",
                bin_name
            );
            return Err(err.into());
        }
    }

    // Binary will be in a 'bin' subdirectory of the --root
    let mut path = install_root.join("bin");
    path.push(true_bin_name);
    Ok(path)
}

/*

use std::fs;
use std::collections::HashMap;
use serde_json::Value;
*/

use error_chain::error_chain;
use std::io::{copy, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::process::{Command, Stdio};

error_chain! {
     foreign_links {
         Io(std::io::Error);
         HttpRequest(reqwest::Error);
     }
}

#[tokio::main]
async fn main() -> Result<()> {

    let cache_dir = "tmp/symbols/cache";
    let dump_dir = "tmp/dumps";

    fs::create_dir_all(cache_dir)?;
    fs::create_dir_all(dump_dir)?;

    let mut args = std::env::args();
    if args.len() != 3 {
        println!("Invalid number of arguments. Usage:");
        println!("socc-pair soccorro_api_token soccorro_crash_id");
        return Ok(())
    }

    let _bin_name = args.next().unwrap();
    let token = args.next().unwrap();
    let socc_id = args.next().unwrap();




    // Download the json socorro has for the minidump
    let socc_json_req = reqwest::Client::new()
        .get("https://crash-stats.mozilla.org/api/ProcessedCrash/")
        .header("Auth-Token", &token)
        .query(&[("crash_id", &*socc_id)]);

    let mut socc_json_path = PathBuf::from(dump_dir).join(&socc_id);
    socc_json_path.set_extension("json");

    let socc_json = fetch(socc_json_req, &socc_json_path).await?;
    let socc_json: serde_json::Value = serde_json::from_reader(socc_json).unwrap();
    let socc_json = socc_json.get("json_dump").unwrap();



    // Download the minidump
    let minidump_req = reqwest::Client::new()
        .get("https://crash-stats.mozilla.org/api/RawCrash/")
        .header("Auth-Token", &token)
        .query(&[("crash_id", &*socc_id), ("format", "raw"), ("name", "upload_file_minidump")]);

    let mut minidump_path = PathBuf::from(dump_dir).join(&socc_id);
    minidump_path.set_extension("dmp");

    fetch(minidump_req, &minidump_path).await?;



    println!("analyzing...");
    // Process the minidump
    let output = Command::new("minidump-stackwalk")
        .arg("--symbols-url=https://symbols.mozilla.org/")
        .arg("--symbols-cache=tmp/symbols/cache")
        .arg(minidump_path)
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    println!("analyzed!");

    let rust_json: serde_json::Value = serde_json::from_reader(&*output.stdout).unwrap();

    compare_crashes(rust_json.as_object().unwrap(), socc_json.as_object().unwrap());

    Ok(())
}

fn compare_crashes(
    rust_json: &serde_json::Map<String, serde_json::Value>, 
    socc_json: &serde_json::Map<String, serde_json::Value>,
) {

    let k = "threads";
    let rust_thread = rust_json.get(k).unwrap();
    let socc_thread = socc_json.get(k).unwrap();

    let (errors, warnings) = recursive_compare(0, k, rust_thread, socc_thread);
    let status = if errors == 0 { "✔" } else { "❌" };
    println!("");
    println!("{} Total errors: {}, warnings: {}", status, errors, warnings);
}

fn recursive_compare(
    depth: usize,
    k: &str,
    rust_val: &serde_json::Value, 
    socc_val: &serde_json::Value,
) -> (u64, u64) {
    use serde_json::Value::*;

    let mut errors = 0;
    let mut warnings = 0;

    match (socc_val, rust_val) {
        (Bool(s), Bool(r)) => {
            if s == r {
                println!("{:width$}✔ {}: {}", "", k, s, width=depth);
            } else {
                errors += 1;
                println!("{:width$}❌", "", width=depth);
                println!("  {:width$}{}: {}", "", k, s, width=depth);
                println!("  {:width$}{}: {}", "", k, r, width=depth);
            }
        }
        (Number(s), Number(r)) => {
            if s == r {
                println!("{:width$}✔ {}: {}", "", k, s, width=depth);
            } else {
                errors += 1;
                println!("{:width$}❌ did not match", "", width=depth);
                println!("  {:width$}{}: {}", "", k, s, width=depth);
                println!("  {:width$}{}: {}", "", k, r, width=depth);
            }
        }
        (String(s), String(r)) => {
            if let (Some(s), Some(r)) = (parse_int(s), parse_int(r)) {
                if s == r {
                    println!("{:width$}✔ {}: 0x{:08x}", "", k, s, width=depth);
                } else {
                    errors += 1;
                    println!("{:width$}❌ did not match", "", width=depth);
                    println!("  {:width$}{}: 0x{:08x}", "", k, s, width=depth);
                    println!("  {:width$}{}: 0x{:08x}", "", k, r, width=depth);
                }
            } else {
                if s == r {
                    println!("{:width$}✔ {}: {}", "", k, s, width=depth);
                } else {
                    errors += 1;
                    println!("{:width$}❌ did not match", "", width=depth);
                    println!("  {:width$}{}: {}", "", k, s, width=depth);
                    println!("  {:width$}{}: {}", "", k, r, width=depth);
                }
            }
        }
        (Object(s), Object(r)) => {
            println!("{:width$} {}: {{", "", k, width=depth);
            let new_depth = depth + 2;
            for (k, s) in s {
                if let Some(r) = r.get(k) {
                    let (new_errors, new_warnings) = recursive_compare(new_depth, k, s, r);
                    errors += new_errors;
                    warnings += new_warnings;
                } else {
                    let useless_fields = ["threads_index", "frames_truncated", "total_frames", "missing_symbols"];
                    if let Null = s {
                        // Ok to be missing a null
                    } else if useless_fields.contains(&&**k) {
                        warnings += 1;
                        println!("{:width$}⚠ ignoring useless field {}: {}", "", k, s, width=new_depth);
                    } else {
                        errors += 1;
                        println!("{:width$}❌ rust was missing {}: {}", "", k, s, width=new_depth);
                    }
                }
            }
            println!("{:width$} }}", "", width=depth);
        }
        (Array(s), Array(r)) => {
            let s_len = s.len();
            let r_len = r.len();
            let len = if s_len < r_len { s_len } else { r_len };
            if s_len != r_len {
                println!("{:width$}❌ different length", "", width=depth);
                errors += 1;
            }
            println!("{:width$} {}: [", "", k, width=depth);
            for i in 0..len {
                let (new_errors, new_warnings) = recursive_compare(depth + 2, &i.to_string(), &s[i], &r[i]);
                errors += new_errors;
                warnings += new_warnings;
            }
            println!(" {:width$}]", "", width=depth);
        }
        (_, Null) => {
            println!("{:width$}❌ rust val was null instead of {}: {}", "", k, socc_val, width=depth);
        }
        _ => {
            println!("{:width$}❌ completely different types for {}", "", k, width=depth);
        }
    }
    (errors, warnings)
}

async fn fetch(request: reqwest::RequestBuilder, path: &Path) -> Result<File> {
    let name = path.file_name().unwrap().to_str().unwrap();
    if let Ok(file) = File::open(path) {
        println!("Had cached {}", name);
        Ok(file)
    } else {

        println!("Downloading {}", name);
        let payload = request
            .send()
            .await?;


        let mut file =  OpenOptions::new()
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
    int.strip_prefix("0x").and_then(|s| u64::from_str_radix(s, 16).ok())
}
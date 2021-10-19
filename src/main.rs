/*

use std::fs;
use std::collections::HashMap;
use serde_json::Value;
*/

use error_chain::error_chain;
use std::io::{BufReader, copy, Seek, SeekFrom};
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
    let socc_json: serde_json::Value = serde_json::from_reader(BufReader::new(socc_json)).unwrap();
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

    let mut rust_json_path = PathBuf::from(dump_dir).join(&socc_id);
    rust_json_path.set_extension("rust.json");
    let mut file =  OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&rust_json_path)?;

    copy(&mut &*output.stdout, &mut file)?;
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

    println!("");
    let (errors, warnings) = recursive_compare(0, k, socc_thread, rust_thread);
    let status = if errors == 0 { "+" } else { "-" };
    println!("");
    println!("{} Total errors: {}, warnings: {}", status, errors, warnings);
}

fn recursive_compare(
    depth: usize,
    k: &str,
    socc_val: &serde_json::Value,
    rust_val: &serde_json::Value, 
) -> (u64, u64) {
    use serde_json::Value::*;

    let mut errors = 0;
    let mut warnings = 0;

    // These fields are either redundant or unimportant. Treat them being missing as only
    // a warning to allow us to focus on more significant problems.
    let useless_fields = ["threads_index", "frames_truncated", "total_frames", "missing_symbols", "frame", "frame_count"];


    match (socc_val, rust_val) {
        (Bool(s), Bool(r)) => {
            if s == r {
                println!(" {:width$}{}: {}", "", k, s, width=depth);
            } else if useless_fields.contains(&k) {
                warnings += 1;
                println!("~{:width$}ignoring useless field {}: {}", "", k, s, width=depth);
            } else {
                errors += 1;
                println!("-{:width$}did not match", "", width=depth);
                println!("+{:width$}{}: {}", "", k, s, width=depth);
                println!("-{:width$}{}: {}", "", k, r, width=depth);
            }
        }
        (Number(s), Number(r)) => {
            if s == r {
                println!(" {:width$}{}: {}", "", k, s, width=depth);
            } else if useless_fields.contains(&k) {
                warnings += 1;
                println!("~{:width$}ignoring useless field {}: {}", "", k, s, width=depth);
            } else {
                errors += 1;
                println!("-{:width$}did not match", "", width=depth);
                println!("+{:width$}{}: {}", "", k, s, width=depth);
                println!("-{:width$}{}: {}", "", k, r, width=depth);
            }
        }
        (String(s), String(r)) => {
            if let (Some(s), Some(r)) = (parse_int(s), parse_int(r)) {
                if s == r {
                    println!(" {:width$}{}: 0x{:08x}", "", k, s, width=depth);
                } else {
                    errors += 1;
                    println!("-{:width$}did not match", "", width=depth);
                    println!("+{:width$}{}: 0x{:08x}", "", k, s, width=depth);
                    println!("-{:width$}{}: 0x{:08x}", "", k, r, width=depth);
                }
            } else {
                if s == r {
                    println!(" {:width$}{}: {}", "", k, s, width=depth);
                } else if k == "trust" {
                    let (s_trust, r_trust) = trust_levels(socc_val, rust_val);
                    if r_trust < s_trust {
                        println!("~{:width$}rust had better trust ({} vs {})", "", s, r, width=depth);
                        warnings += 1;
                    } else if s_trust < r_trust {
                        println!("-{:width$}socc had better trust ({} vs {})", "", s, r, width=depth);
                        errors += 1;
                    } else {
                        // Shouldn't be possible? I want to know if this happens.
                        unreachable!()
                    }
                } else {
                    errors += 1;
                    println!("-{:width$}did not match", "", width=depth);
                    println!("+{:width$}{}: {}", "", k, s, width=depth);
                    println!("-{:width$}{}: {}", "", k, r, width=depth);
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
                        println!("~{:width$}ignoring useless field {}: {}", "", k, s, width=new_depth);
                    } else {
                        errors += 1;
                        println!("-{:width$}rust was missing", "", width=new_depth);
                        println!("+{:width$}{}: {}", "", k, s, width=new_depth);
                    }
                }
            }
            println!("{:width$} }}", "", width=depth);
        }
        (Array(s), Array(r)) => {
            // The bulk of the refined analysis happens here, as we try to more intelligently
            // handle the array of frames in a backtrace. This is important because very small
            // differences can naively become massive differences. For instance if one backtrace
            // contains an extra frame, naive comparison would report that every single frame
            // after that point is different!
            let s_len = s.len();
            let r_len = r.len();
            let len = if s_len < r_len { s_len } else { r_len };
            
            println!("{:width$} {}: [", "", k, width=depth);
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
                    if let (Some(String(s_func)), Some(String(r_func))) = (s_obj.get("function"), r_obj.get("function")) {
                        if s_func != r_func {

                            // Assume one of the values is "good" and scan ahead in the other for a match
                            let try_lookahead = |
                                good: &serde_json::Map<std::string::String, 
                                serde_json::Value>, 
                                bad_arr: &[serde_json::Value], 
                                current_idx: usize
                            | {
                                for i in 1..4 {
                                    if let Some(Object(bad)) = bad_arr.get(current_idx + i) {
                                        if let (Some(String(good_func)), Some(String(bad_func))) = (good.get("function"), bad.get("function")) {
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
                            let (s_trust, r_trust) = trust_levels(s_obj.get("trust").unwrap(), r_obj.get("trust").unwrap());
                            if let Some(r_skip) = try_lookahead(&s_obj, &r, r_offset) {
                                // We found a match further along the rust array, print the frames we're
                                // skipping more concisely and jump ahead in rust's stream.  
                                for i in 0..r_skip {
                                    let r_offset = r_offset + i;
                                    let r_val = &r[r_offset];
                                    if s_trust <= r_trust  {
                                        errors += 1;
                                        println!("-{:width$}rust had extra array value:", "", width=new_depth);
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
                                        println!("-{:width$}socc had extra array value:", "", width=new_depth);
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
                let (new_errors, new_warnings) = recursive_compare(new_depth, &s_offset.to_string(), s_val, r_val);
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
                if let (Some(s_trust), Some(r_trust)) = (s[s_offset - 1].get("trust"), r[r_offset - 1].get("trust")) {
                    let trust = trust_levels(s_trust, r_trust);
                    last_s_trust = trust.0;
                    last_r_trust = trust.1;
                }
            }

            // Display non-paired values
            for i in s_offset..s_len {
                if last_s_trust <= last_r_trust  {
                    errors += 1;
                    println!("-{:width$}rust was missing array value:", "", width=new_depth);
                } else {
                    warnings += 1;
                    println!("~{:width$}rust was missing array value (but rust has better trust):", "", width=new_depth);
                }
                recursive_print(new_depth, &i.to_string(), &s[i]);
            }
            for i in r_offset..r_len {
                if last_s_trust <= last_r_trust {
                    errors += 1;
                    println!("-{:width$}rust had extra array value:", "", width=new_depth);
                } else {
                    warnings += 1;
                    println!("~{:width$}rust had extra array value (but rust has better trust):", "", width=new_depth);
                }
                recursive_print(new_depth, &i.to_string(), &r[i]);
            }
            println!(" {:width$}]", "", width=depth);
        }
        (_, Null) => {
            println!("-{:width$}rust val was null instead of:", "", width=depth);
            recursive_print(depth, k, socc_val);
        }
        _ => {
            println!("-{:width$}completely different types for {}:", "", k, width=depth);
            println!("+");
            recursive_print(depth+2, k, socc_val);
            println!("-");
            recursive_print(depth+2, k, rust_val);
        }
    }
    (errors, warnings)
}

fn recursive_print(
    depth: usize,
    k: &str,
    val: &serde_json::Value
) {
    use serde_json::Value::*;

    match val {
        Bool(val) => {
            println!("{:width$} {}: {}", "", k, val, width=depth);
        }
        Number(val) => {
            println!("{:width$} {}: {}", "", k, val, width=depth);
        }
        String(val) => {
            println!("{:width$} {}: {}", "", k, val, width=depth);
        }
        Object(val) => {
             println!("{:width$} {}: {{", "", k, width=depth);
            for (k, v) in val {
                recursive_print(depth+2, k, v);
            }
            println!("{:width$} }}", "", width=depth);
        }
        Array(val) => {
            println!("{:width$} {}: [", "", k, width=depth);
            for i in 0..val.len() {
                recursive_print(depth+2, &i.to_string(), &val[i]);
            }
            println!("{:width$} ]", "", width=depth);
        }
        Null => {
            println!("{:width$} {}: null", "", k, width=depth);
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

fn trust_levels(    
    socc_val: &serde_json::Value,
    rust_val: &serde_json::Value, 
) -> (usize, usize) {
    use serde_json::Value::*;
    let trust_levels = &["context", "cfi", "cfi_scan", "frame_pointer", "scan"];
    if let (String(s_trust), String(r_trust)) = (socc_val, rust_val) {
        let s_trust_level = trust_levels.iter().position(|x| x==s_trust).unwrap_or(99);
        let r_trust_level = trust_levels.iter().position(|x| x==r_trust).unwrap_or(99);
        (s_trust_level, r_trust_level)
    } else {
        (99, 99)
    }
}
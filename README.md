# socc-pair

A test harness for testing, debugging, and benchmarking rust-minidump's minidump-stackwalk,
and Firefox crash reports.

This was originally designed to check that rust-minidump was the same (or better) output
than the breakpad fork Mozilla was running in production. But since rust-minidump is now
the production implementation, it's grown into a tool for helping you:

* Dig deeper into the contents of a Firefox crash report (what's the actual value in the minidump?)
* Debug why rust-minidump produced a particular value (why did the backtrace not use CFI here?)
* Test and Benchmark local changes against "real" inputs (oops, I accidentally broke this field in the schema!)


## Usage

```
socc-pair --api-token=YOUR_TOKEN --crash-id=SOME_CRASH_ID
```

e.g.

```
socc-pair --api-token=f0c129d4467bf58eeca0ad8e8e5d --crash-id=cd121a28-ca2b-48c2-a0d4-a71a40210915
```

This will produce a kind-of-diff of the two json files, but with more intelligent domain-specific
analysis. At the end of the output, you will get a final count of errors and warnings, as well
as paths to all the different input/output files used.

You will need a socorro [API key](https://crash-stats.mozilla.org/api/tokens/) with the following permissions:

* "View Raw Dumps"
* "View Personal Identifiable Information" (to read some entries in raw-json)

If you don't wish to use the second permission, you can set `--raw-json=none` to skip the raw json.

Note that by default we assume you have rust-minidump's `minidump-stackwalk` binary installed on your path 
(`cargo install minidump-stackwalk`).

### Notable Optional Arguments

* `--run-local=path` - specify a path to a checkout of `minidump-stackwalk` that socc-pair should compile and use.
* `--bench=times` - run minidump-stackwalk the given number of times to benchmark it.
* `--output-file=path` - write all output to a file (if you make it a .diff, editors will syntax highlight the json diff!).
* `--clean-cache` - clear all caches, including the symbol cache before each benchmark iteration (careful!).
* `--skip-diff` - disable json diffing (nice when you're focused on benching).
* `--no-symbols` - prevent minidump-stackwalk from getting any symbol files, to test that situation.
* `--mock-server` - (UNDER CONSTRUCTION) create a local symbol server to test networking without killing your internet.



## Example Execution

A situation socc-pair is designed for is testing the impact of local changes.
Here we really flex that ability by having it:

* download a minidump we think is interesting from socorro (default)
* compile and use a local checkout of rust-minidump, to test our changes
* use mozilla's symbol servers to symbolicate/unwind (default)
* diff our local results against the value in production (default)
* benchmark our local changes by running minidump-stackwalk repeatedly
* dump all intermediate results to files so we can debug any issues (default)
* pipe everything to a "diff" file to get syntax highlighting on the report

(Note, by enabling benchmarking we auto-disable the stack unwinder trace logging.
This makes results more accurately reflect a production configuration, but means
you may want to stop benchmarking when debugging stackwalking.)


```sh
socc-pair 
   --api-token=f0c129d4467bf58eeca0ad8e8e5d 
   --crash-id=b4f58e9f-49be-4ba5-a203-8ef160211027
   --build-local=/Users/ABeingessner/dev/rust-minidump/minidump-stackwalk/
   --bench=5
   --output-file=output.diff
```

```diff
NOTE: setting minidump-stackwalk --verbose to 'error' for benchmarking

Had cached 082a152f-05b4-4de9-943b-c30550211210.dmp
Had cached 082a152f-05b4-4de9-943b-c30550211210.json
Had cached 082a152f-05b4-4de9-943b-c30550211210.raw.json

building local minidump-stackwalk...
    Finished release [optimized] target(s) in 0.11s
built /Users/ABeingessner/dev/rust-minidump/target/release/minidump-stackwalk

running local minidump-stackwalk... (5 times)
done! (1/5)
done! (2/5)
done! (3/5)
done! (4/5)
done! (5/5)
all done!

comparing json...

 : {
   crash_info: {
     address: 0x7fff1760aca0
     crashing_thread: 8
     type: EXCEPTION_BREAKPOINT
   }
   crashing_thread: {
     frames: [
       0: {
         file: hg:hg.mozilla.org/mozilla-central:mozglue/static/rust/wrappers.cpp:1750da2d7f9db490b9d15b3ee696e89e6aa68cb7
         frame: 0
         function: RustMozCrash(char const*, int, char const*)
         function_offset: 0x00000010
-        did not match
+        line: 17
-        line: 20
         module: xul.dll

.....
.....
.....

   unloaded_modules: [
     0: {
       base_addr: 0x7fff48290000
-      local val was null instead of:
       code_id: 68798D2F9000
       end_addr: 0x7fff48299000
       filename: KBDUS.DLL
     }
     1: {
       base_addr: 0x7fff56020000
       code_id: DFD6E84B14000
       end_addr: 0x7fff56034000
       filename: resourcepolicyclient.dll
     }
   ]
~  ignoring field write_combine_size: "0"
 }
 
 - Total errors: 288, warnings: 39

benchmark results (ms):
  2388, 1986, 2268, 1989, 2353, 
average runtime: 00m:02s:196ms (2196ms)
median runtime: 00m:02s:268ms (2268ms)
min runtime: 00m:01s:986ms (1986ms)
max runtime: 00m:02s:388ms (2388ms)

max memory (rss) results (bytes):
  267755520, 261152768, 272441344, 276131840, 279134208, 
average max-memory: 258MB (271323136 bytes)
median max-memory: 259MB (272441344 bytes)
min max-memory: 249MB (261152768 bytes)
max max-memory: 266MB (279134208 bytes)

Output Files: 
  * (download) Minidump: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.dmp
  * (download) Socorro Processed Crash: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.json
  * (download) Raw JSON: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.raw.json
  * Local minidump-stackwalk Output: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.local.json
  * Local minidump-stackwalk Logs: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.log.txt

``` 




## Debugging Backtraces

See [the upstream debugging docs](https://github.com/luser/rust-minidump/tree/master/minidump-stackwalk#debugging-stackwalking).

socc-pair will capture and store the logging output of rust-minidump (see the "Local minidump-stackwalk Logs" path at the end of the above example). socc-pair also configures
rust-minidump to use `trace` logging by default, which includes a detailed trace of how it
performed each stackwalk.

(If logging is misbehaving, it can be configured with `--verbose`)

Some tips on reading these logs:

* All unwinding lines will start with `[TRACE] unwind` (other logs may get interspersed).
* Each thread's unwind will: 
  * start with "starting stack unwind" 
  * end with "finished stack unwind"
* Each frame's unwind will: 
  * start with "unwinding \<name\>"
  * end with "\<unwinding method\> seems valid"
  * include the final instruction pointer and stack pointer values at the end
* The methods used to unwind are tried in order (decreasing in quality)
  * cfi
  * frame pointer
  * scan


If you see "trying scan" or "trying framepointer", this means the previous
unwinding method failed. Sometimes the reason for failure will be logged, 
but other times the failure is in a weird place I don't have any logging for.
If that happens, you can still potentially infer what went wrong based on what
usually comes after that step.

For instance, a cfi trace typically looks like:

```text
[TRACE] unwind: unwinding NtGetContextThread
[TRACE] unwind: trying cfi
[TRACE] unwind: found symbols for address, searching for cfi entries
```

If you instead see:

```text
[TRACE] unwind: unwinding NtGetContextThread
[TRACE] unwind: trying cfi
[TRACE] unwind: trying frame pointer
```

This suggests the cfi analysis couldn't *even* get to "found symbols for address". So,
presumably, it *couldn't* find symbols for the current instruction pointer. This may 
be because it didn't map to a known module, or because there were no symbols for that module.




### Example Trace

```text
[TRACE] unwind: starting stack unwind
[TRACE] unwind: unwinding NtGetContextThread
[TRACE] unwind: trying cfi
[TRACE] unwind: found symbols for address, searching for cfi entries
[TRACE] unwind: trying STACK CFI exprs
[TRACE] unwind:   .cfa: $rsp 8 + .ra: .cfa 8 - ^
[TRACE] unwind:   .cfa: $rsp 8 +
[TRACE] unwind: STACK CFI parse successful
[TRACE] unwind: STACK CFI seems reasonable, evaluating
[TRACE] unwind: successfully evaluated .cfa (frame address)
[TRACE] unwind: successfully evaluated .ra (return address)
[TRACE] unwind: cfi evaluation was successful -- caller_ip: 0x000000ec00000000, caller_sp: 0x000000ec7fbfd790
[TRACE] unwind: cfi result seems valid
[TRACE] unwind: unwinding 1013612281855
[TRACE] unwind: trying cfi
[TRACE] unwind: trying frame pointer
[TRACE] unwind: trying scan
[TRACE] unwind: scan seems valid -- caller_ip: 0x7ffd172c2a24, caller_sp: 0xec7fbfd7f8
[TRACE] unwind: unwinding <unknown in ntdll.dll>
[TRACE] unwind: trying cfi
[TRACE] unwind: found symbols for address, searching for cfi entries
[TRACE] unwind: trying frame pointer
[TRACE] unwind: trying scan
[TRACE] unwind: scan seems valid -- caller_ip: 0x7ffd162b7034, caller_sp: 0xec7fbfd828
[TRACE] unwind: unwinding BaseThreadInitThunk
[TRACE] unwind: trying cfi
[TRACE] unwind: found symbols for address, searching for cfi entries
[TRACE] unwind: trying STACK CFI exprs
[TRACE] unwind:   .cfa: $rsp 8 + .ra: .cfa 8 - ^
[TRACE] unwind:   .cfa: $rsp 48 +
[TRACE] unwind: STACK CFI parse successful
[TRACE] unwind: STACK CFI seems reasonable, evaluating
[TRACE] unwind: successfully evaluated .cfa (frame address)
[TRACE] unwind: successfully evaluated .ra (return address)
[TRACE] unwind: cfi evaluation was successful -- caller_ip: 0x0000000000000000, caller_sp: 0x000000ec7fbfd858
[TRACE] unwind: cfi result seems valid
[TRACE] unwind: instruction pointer was nullish, assuming unwind complete
[TRACE] unwind: finished stack unwind
```

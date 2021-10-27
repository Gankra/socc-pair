# socc-pair

Compares rust-minidump's minidump-stackwalk output to socorro.

## Usage

```
socc-pair --api-token=YOUR_TOKEN --crash-id=SOME_CRASH_ID

e.g.

socc-pair --api-token=f0c129d4467bf58eeca0ad8e8e5d --crash-id=cd121a28-ca2b-48c2-a0d4-a71a40210915
```

This will produce a kind-of-diff of the two json files, but with more intelligent domain-specific
analysis. At the end of the output, you will get a final count of errors and warnings, as well
as paths to all the different input/output files used.

You will need a socorro [API key](https://crash-stats.mozilla.org/api/tokens/) with the following permissions:

* "View Raw Dumps"
* "View Personal Identifiable Information" (to read some entries in raw-json)

If you don't wish to use the second permission, you can set `--raw-json=none` to skip the raw json.

Note that this assumes you have rust-minidump's `minidump-stackwalk` binary installed on your path (cd into that subcrate and `cargo install --path ./`)

## Example Execution

```diff
socc-pair --api-token=f0c129d4467bf58eeca0ad8e8e5d --crash-id=b4f58e9f-49be-4ba5-a203-8ef160211027

Had cached b4f58e9f-49be-4ba5-a203-8ef160211027.dmp
Had cached b4f58e9f-49be-4ba5-a203-8ef160211027.json
Had cached b4f58e9f-49be-4ba5-a203-8ef160211027.raw.json
analyzing...
analyzed!

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
-      rust val was null instead of:
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

- Total errors: 50, warnings: 51

Output Files: 
  * Minidump: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.dmp
  * Socorro Processed Crash: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.json
  * Raw JSON: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.raw.json
  * Local minidump-stackwalk Output: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.local.json
  * Local minidump-stackwalk Logs: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.log.txt

``` 







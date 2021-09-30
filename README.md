# socc-pair
Compares rust-minidump's minidump-stackwalk output to socorro.

Usage:

```
socc-pair socorro_api_key socorro_crash_id

e.g.

socc-pair f0c129d4467bf58eeca0ad8e8e5d cd121a28-ca2b-48c2-a0d4-a71a40210915
```

You will need a socorro [API key](https://crash-stats.mozilla.org/api/tokens/) with the "View Raw Dumps" permission.

Note that this assumes you have rust-minidump's `minidump-stackwalk` binary installed on your path (cd into that subcrate and `cargo install --path ./`)

Currently hardcoded to download files to a new `./tmp/` directory for a bit more portability/persistence, so you can do more analysis on the dumps/json later. 
But the dumps contain private info so be sure to delete that eventually!




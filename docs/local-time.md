# Local time

## Local time

The C library resolves the local time zone inside itself, where no hook sees it: glibc reads `TZ`
and opens the zone file through its own internal calls, and macOS's libc and CoreFoundation run
from the shared cache. A sim that decides its zone — `TZ` set in an isolated environment
(`HostProfile::env`, `isolate_env`), or an `/etc/localtime` its `VirtualFs` serves — has snare
resolve it instead, following tzset(3), and read the files through the sim's file plane, so
declined paths reach the real ones:

- `TZ` unset: `/etc/localtime` (a symlink into the real `/usr/share/zoneinfo` is followed), or
  UTC when there is none.
- `TZ` empty: UTC.
- `TZ` (after an optional `:`) names an absolute TZif file or one under `TZDIR`
  (`/usr/share/zoneinfo` by default), or is a POSIX TZ string such as `EST5EDT,M3.2.0,M11.1.0`.

```rust
use snare::{FsBuilder, HostProfile, Sim};

let host = HostProfile::new().env("TZ", "Asia/Tokyo").build();
Sim::builder().host(host).build().run(|| {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&1_700_000_000, &mut tm) };
    assert_eq!(tm.tm_gmtoff, 9 * 3600);
});

let fs = FsBuilder::new().symlink("/etc/localtime", "/usr/share/zoneinfo/Europe/Oslo");
let host = HostProfile::new().isolate_env().build();
Sim::builder().fs(fs.build()).host(host).build().run(|| {
    // localtime_r reports CET; on macOS iana-time-zone reports "Europe/Oslo".
});
```

`localtime_r`, `localtime`, `mktime`, `timelocal`, `ctime_r` and `ctime` use that zone, `tzset`
makes every thread resolve it again, and on macOS `CFTimeZoneCopySystem` and
`CFTimeZoneCopyDefault` return a CoreFoundation zone of the same name (or built from the sim's
TZif bytes), so `time`'s `UtcOffset::current_local_offset`, `iana-time-zone` and anything else
reading local time through them see the sim's zone; chrono and jiff read `TZ` and
`/etc/localtime` themselves. `mktime` searches as the C library does, step for step: glibc's from
the offset its previous call found, which the sim keeps per sim as glibc keeps it per process,
and tzcode's by bisection, so gaps, a `tm_isdst` the time does not have, and which instant a
repeated local time with a negative `tm_isdst` names all come out as the host's. `strftime`
(and `strftime_l`, `wcsftime`, `wcsftime_l`) prints the sim's zone where the C library reads its
own: `%Z` of a `struct tm` without a zone name (the sim's copy of `tzname`, which its conversions
move as the C library's move it), `%s`, and macOS's `%z`, which reads `timezone` and `altzone`
rather than `tm_gmtoff`. `local_time_os_truth` checks all of it against glibc and tzcode in
sixteen zones. A sim that decides no zone — no isolated environment and no `/etc/localtime` of
its own, as a plain `Sim` — leaves local time to the C library and the machine's zone. See
[OPEN_BUGS.md](../OPEN_BUGS.md) for what stays process-wide.

### Windows

A Windows sim decides its zone with `SimBuilder::time_zone`: an IANA name, which stands for the
Windows zone the Unicode CLDR maps it to (`windowsZones.xml` with every territory's names and
their aliases, bundled), or a Windows zone's registry key name. The zone's rules come from the
machine's registry, year by year (dynamic daylight saving time), and every conversion is handed
to Windows with the zone named, in the form that measured identical to Windows with the machine
set to that zone:

```rust
use snare::Sim;

Sim::builder().time_zone("Europe/Oslo").build().run(|| {
    // GetDynamicTimeZoneInformation names "W. Europe Standard Time"; chrono's Local, time's
    // local offset and jiff's system zone (which jiff names Europe/Berlin) are an hour or two
    // ahead of UTC; _localtime64_s and strftime's %Z agree.
});
```

- `GetTimeZoneInformation` and `GetDynamicTimeZoneInformation` give the rule of the current year
  and whether daylight saving time is in effect now; `GetTimeZoneInformationForYear` with no zone,
  `SystemTimeToTzSpecificLocalTime` and `TzSpecificLocalTimeToSystemTime` with no zone or the
  current rule, and their `Ex` forms with no zone, convert in the sim's zone (chrono reads
  `GetTimeZoneInformationForYear`, `time` `SystemTimeToTzSpecificLocalTime`, jiff the dynamic
  information's key name).
- `FileTimeToLocalFileTime`, `LocalFileTimeToFileTime` and `GetLocalTime` use the offset in
  effect now, and so do the UCRT's `_strtime` and `_strdate` (and their wide and `_s` forms);
  `GetSystemTime` reads the sim's clock.
- The UCRT keeps its zone in globals of its own and converts inside itself. A sim with a zone
  gets a copy of that state, starting as a new process's does (Pacific time, until a call sets
  the zone): `_tzset`, `_get_timezone`, `_get_daylight`, `_get_dstbias`, `_get_tzname` and the
  `_timezone`, `_daylight`, `_dstbias` and `_tzname` globals (reached through `__timezone()` and
  the rest, so each sim has its own), `_localtime64_s`, `_localtime32_s`, `localtime`, `_mktime64`,
  `_mktime32`, `ctime` and its variants, strftime's `%z` and `%Z` and `_ftime64` follow the UCRT's
  rules, which apply the current year's rule to every year. With `TZ` in the C runtime's
  environment the UCRT ignores the machine's zone, and so does the sim.

"Now" is the sim's clock, so a sim on a virtual clock without a zone of its own gets the machine's
zone at the sim's time for the calls that depend on now. `local_time_win` checks the Win32 calls
and the UCRT against the machine's zone and pins values measured with the machine set to other
zones.

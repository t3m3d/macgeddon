# macgeddon

An [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) port to
[Krypton](https://www.krypton-lang.org) for macOS on Apple Silicon — a
KryptScript CLI plus an Objective-K (Choc/AppKit) front end.

It keeps airgeddon's shape: pick an interface, do recon, pick a target,
capture, crack, report. What it does *not* do is pretend. On macOS the
capture half of airgeddon is not implementable, so macgeddon ports the half
that works properly and states the blocker clearly for the other half.

```
$ macgeddon status
+----------------------------------------------------------------------------+
| macgeddon 0.1.0                                                            |
+----------------------------------------------------------------------------+

host   studio  brian
system macOS 27.3 (26C5035r)  Apple M4 Pro

  [wifi] en0   Wi-Fi                     68:5e:dd:81:79:18
  ...
  radio   Apple Silicon radio exposes no monitor mode (en0)
```

## What actually works on this platform

| airgeddon capability | macgeddon | why |
| --- | --- | --- |
| interface inventory | **yes** | `networksetup -listallhardwareports` |
| current network recon (SSID/BSSID/channel/band/RSSI/security) | **yes** | `system_profiler SPAirPortDataType` |
| target list + sorting + session persistence | **yes** | pure Krypton |
| parse saved scans (row lists, legacy `airport -s`, profiler) | **yes** | `scan --file` |
| offline handshake cracking | **yes** | `aircrack-ng` (CPU) |
| monitor-mode capture via a Linux host | **yes** | `--host` runs the real `airmon-ng` + `airodump-ng` there |
| deauth to force a handshake | **yes** | `--host ... --deauth N` runs `aireplay-ng` there |
| offline PMKID / 22000 cracking | **yes** | `hashcat` (Metal on Apple Silicon) |
| pcap → hashcat conversion | **yes** | `hcxpcapngtool` |
| reports / capability matrix / tool doctor | **yes** | pure Krypton |
| monitor mode | **no** | driver exposes no monitor ioctl |
| frame injection / deauth | **no** | no userland 802.11 TX path |
| handshake capture (EAPOL) | **no** | needs monitor mode |
| PMKID capture | **no** | needs monitor mode |
| evil twin / captive portal | **no** | needs AP mode + injection |
| WPS attacks | **no** | needs monitor mode + injection |

### Why capture is gated

This is not a missing feature in the port, it is the platform — and none of it
is a knock on airgeddon, which runs well on Linux precisely because the kernel
there exposes monitor mode and packet injection:

* Apple Silicon Wi-Fi drivers provide **no monitor mode** and **no frame
  injection** to userland. There is no ioctl, no driver flag, no entitlement.
* The `airport` utility that airgeddon-era scripts relied on was **removed in
  macOS 14.4**. `wdutil`, its replacement, has **no scan command** — only
  `diagnose`, `info`, `log`, `dump`, `clean` and `privateMAC`. `info` needs
  root, describes only the current link, and cannot change radio mode, so it is
  not a stand-in for `airmon-ng`.
* `airmon-ng` and `aireplay-ng` install with the aircrack-ng suite on macOS,
  but they drive Linux wireless tooling (`iw`/`iwconfig`). There is no macOS
  equivalent for an Apple Wi-Fi radio, so macgeddon never calls them; from that
  suite it uses `aircrack-ng` only, for offline cracking.
* `tcpdump -I` (monitor mode) fails on these radios; `tcpdump` alone captures
  IP traffic on the managed interface, which never contains 802.11 headers or
  EAPOL frames.

So the honest workflow on a Mac is:

1. Capture on a Linux host with an injection-capable adapter (or use a
   dedicated device such as a Hak5 Mark VII radio).
2. Bring the `.pcap` / `.pcapng` / `.22000` back to the Mac.
3. `macgeddon crack --cap capture.pcap --wordlist rockyou.txt` — this runs at
   full Metal speed on Apple Silicon.

`macgeddon capture --explain` prints the same story in the terminal.

## Install

Requirements:

* macOS on Apple Silicon (arm64)
* Krypton 2.4.x — `kcc` at `/usr/local/bin/kcc`
  (`brew install --cask t3m3d/krypton/krypton` or the installer from
  [krypton-lang.org/downloads](https://www.krypton-lang.org/downloads.html))
* optional, for offline cracking: `brew install aircrack-ng hashcat hcxtools`

> **Compiler name collision:** macOS ships `/usr/bin/kcc` (Heimdal Kerberos).
> It shadows the Krypton compiler on a default `PATH`. Every script here uses
> an absolute path; use `/usr/local/bin/kcc` too.

## Build

```sh
./scripts/build.sh          # CLI + GUI + tests
./scripts/build.sh build    # binaries only
./scripts/build.sh test     # test suite only
./scripts/build.sh clean
```

Outputs: `bin/macgeddon`, `bin/macgeddon-gui`, `bin/tests`.
Override the compiler with `KCC=/path/to/kcc`.

## Usage

```sh
macgeddon                     # interactive menu (airgeddon style)
macgeddon status              # interface, current network, radio verdict
macgeddon caps                # full capability matrix
macgeddon ifaces              # hardware port table
macgeddon scan                # read the associated network
macgeddon scan --save         # ... and store targets in the session
macgeddon scan --file s.txt   # parse a saved scan (row list / airport / profiler)

macgeddon capture --explain   # why monitor mode is unavailable here
macgeddon capture --secs 30   # BPF capture on the managed interface
macgeddon capture --monitor   # one honest monitor-mode attempt

macgeddon crack --cap cap.pcap --wordlist rockyou.txt [--bssid MAC]
macgeddon crack --hash cap.22000 --wordlist rockyou.txt [--mask '?d?d?d?d?d?d?d?d']
macgeddon crack --convert cap.pcapng        # -> hashcat 22000 via hcxtools

macgeddon report              # session summary + JSON report
macgeddon doctor              # toolchain status and install hints
```

State lives in `~/.macgeddon` (override with `MACGEDDON_HOME`):

```
sessions/last.json   machine-readable session
targets.txt          parsed targets (one record per line)
captures/            pcaps, hashes, tool logs
reports/             JSON reports
```

### Getting a neighbourhood scan

macOS has no supported neighbour-scan command:

* `airport -s` was removed in macOS 14.4.
* `wdutil`, the Wireless Diagnostics tool that replaced it, has **no `scan`
  subcommand**. `strings` on `/usr/bin/wdutil` shows only `clean`, `diagnose`,
  `dump` and `info` as command words, and `wdutil scan` prints its usage text.
  Its `info` command needs root, describes the current link, and cannot change
  radio mode, so it cannot replace `airmon-ng` either.
* `wdutil info` does print a `ScanResults` key, which is easy to mistake for a
  scan. It is cached state from the system's own scan, not a fresh
  enumeration, and current builds still redact SSID/BSSID.
* `system_profiler SPAirPortDataType` lists cached neighbour networks
  unprivileged (channel and security, usually without RSSI or BSSID), and
  `macgeddon scan` reads exactly that.
* Apple's only live scan is the **Wireless Diagnostics app's Scan window**
  (Option-click the Wi-Fi menu → Wireless Diagnostics → Window → Scan). It is
  GUI-only and has no scriptable output.

For a live scan with signal data that you can parse here, scan from a Linux
host or with a third-party scanner, then feed the saved text in:

```sh
macgeddon scan --file scan.txt --save
```

macgeddon never invokes `sudo` on your behalf — it prints the command instead
of prompting into a non-interactive shell.

### The team model: airgeddon's tools, split across machines

macgeddon uses the same toolchain airgeddon does, on whichever machine can
actually run each part:

| Job | airgeddon tool | where | macgeddon |
| --- | --- | --- | --- |
| monitor mode | `airmon-ng` | Linux host | via `--host` |
| recon / capture | `airodump-ng` | Linux host | `scan --host`, `capture --host` |
| deauth to force a handshake | `aireplay-ng` | Linux host | `capture --host --deauth 8` |
| PMKID / handshake dump | `hcxdumptool` | Linux host | optional on the host |
| pcap conversion | `hcxpcapngtool` | this Mac | `crack --convert` |
| offline crack | `aircrack-ng`, `hashcat` | this Mac (Metal) | `crack --cap` / `--hash` |

Nothing is replaced by a pretend equivalent. If a tool cannot run on the Mac,
the real one runs on the host that can, and the artefacts come back over SSH.

```sh
export MACGEDDON_HOST=user@linux-box
export MACGEDDON_PORT=22            # optional

macgeddon host --check              # is the airgeddon toolchain there?
macgeddon scan --host user@linux-box --save
macgeddon capture --host user@linux-box --bssid AA:BB:CC:DD:EE:FF --channel 6 --secs 45
macgeddon crack --cap ~/.macgeddon/captures/cap-YYYYmmdd-HHMMSS.pcap --wordlist rockyou.txt
```

The host needs `airmon-ng`, `airodump-ng`, `aireplay-ng`, an adapter that
supports monitor mode, and passwordless `sudo -n` for unattended runs.
`macgeddon host --check` lists exactly which of those is missing. Every remote
command is printed before it runs, and `timeout` on the host bounds each
capture so an interrupted Mac cannot leave `airodump-ng` running.

## Architecture

```
src/util.k        records, comma-lists, char scanning, colour, shell, JSON
src/model.k       Iface / AP / Cap / Artifact / Session + formatting
src/platform.k    host, permission and toolchain probes, capability matrix
src/wifi.k        interface discovery, current network, monitor-mode verdict
src/scan.k        scan parsers (system_profiler, airport, airodump CSV)
src/capture.k     capture preflight, managed-interface capture, gating
src/crack.k       artifact inventory, conversion, aircrack/hashcat, doctor
src/report.k      session JSON, summaries, report output
src/remote.k      Linux capture host over SSH (airmon-ng/airodump-ng/aireplay-ng)
src/macgeddon.ks  CLI: argument parsing, subcommands, interactive menu
src/ui.k          Objective-K GUI (compile target bin/macgeddon-gui)
tests/            offline test suite + text fixtures
```

Modules are separate files for readability but are compiled as **one
translation unit** (`build.sh` concatenates them in dependency order, stripping
`module` lines). Two documented Krypton rules make this the simplest dependable
build: a relative import carries its extension (`import "util.k"`, not
`import "util"`), and a function name that matches a builtin resolves to the
builtin — so helpers here avoid reserved names such as `lines`. The GUI is
compiled standalone and therefore defines its own helpers.

### Krypton rules this port follows

Verified against the macOS arm64 2.4.9 compiler and its published language
reference. Each rule is enforced in the code below.

* **Builtin names are reserved.** `lines` is a builtin (it returns its text
  argument unchanged), so a user `func lines(...)` is never reached. Helpers use
  non-builtin names (`textLines`); check a name against the builtin table before
  defining it.
* **Two boolean conventions, deliberately.** Builtin predicates (`startsWith`,
  `endsWith`) return booleans and are used directly in `if`. Helpers that
  `emit "1"`/`emit "0"` return text, and `"0"` is truthy, so those are always
  compared (`== "1"`).
* **Index with integers.** `s[i]` yields the byte at an integer index — `s[2]`
  of `"abcdef"` is `"c"`. A text index such as `s["3"]` returns `""` rather than
  raising, so indices always come from integer counters.
* **`\n` is an escape; `\r` is not.** `"\n"` is a newline and `lineCount` agrees,
  but a `"\r"` literal stays as backslash + `r`, which shifts every length. A
  carriage return is written `fromCharCode(13)`, and `replace()` then removes it
  correctly.
* **`len()` measures text.** Handing it an integer traps, so values are coerced
  (`"" + n`) before measuring; that is why `padR`/`padL` route their width
  through text.
* **`count("")` is 1.** `count` counts comma-list items and empty text is one
  empty item; use `len`/`lineCount` to test emptiness.
* **A comma-list cannot hold commas**, so records use US (`0x1f`) as the field
  separator and line parsing replaces commas with spaces.
* **Forward references inside a file fail codegen**, so helpers are defined
  before callers.
* Entry body belongs in `run.k` (warning today, error in 2.4+); `build.sh`
  assembles `run.k` accordingly.

## Tests

```sh
./scripts/build.sh test
```

Offline, no root, no radio, no network: every parser runs against
`tests/fixtures/*` (a realistic `system_profiler` dump, a legacy `airport -s`
table, a generic row-list scan). Coverage includes record encoding, band and
security normalisation, all three scan parsers, sort/dedupe, target
persistence round-trip, report JSON and cracking-command construction.

## Legal

Use only on networks you own or have explicit written permission to test.
Unauthorised interception of wireless traffic is illegal in most
jurisdictions. macgeddon deliberately refuses to fabricate captures it cannot
honestly produce.

## License

GPL-3.0, inherited from airgeddon (see `LICENSE`).

# macgeddon

Native Krypton CLI and AppKit app for macOS on Apple Silicon. Targets M1,
M2, M3, M4, and M5 Macs with one arm64 build; hardware behavior must be
verified on each model. iPhone/iPad, Intel Macs, Rosetta, and Linux are outside
this build's scope.

Inspired by [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon).
This is a macOS subset, not full airgeddon feature parity.

## Build and run

Install [Krypton](https://krypton-lang.org/downloads.html), then:

```sh
./scripts/build.sh
./bin/macgeddon help
./bin/macgeddon status
open ./bin/Macgeddon.app
```

Builds use the installed Homebrew toolchain when available, otherwise
`/usr/local/krypton`. For a custom toolchain set **both** `KCC` (absolute
compiler path) and `KRYPTON_ROOT` (matching installation root). Apple's
`/usr/bin/kcc` is a Kerberos utility, not this compiler.

```sh
./scripts/build.sh build   # CLI, GUI, signed development app bundle
./scripts/build.sh test    # offline Krypton unit tests
python3 tests/smoke.py     # CLI and bundle integration checks after building
./scripts/build.sh clean
```

Outputs are `bin/macgeddon`, `bin/macgeddon-gui`, and `bin/Macgeddon.app`.
The app includes its own CLI; it runs without the source directory or Krypton
installed. Copy the complete `.app` when moving it. `macgeddon-gui` outside
its bundle needs `macgeddon` beside it. The GUI has scrollable, selectable
output, Copy/Select All, native resizing, and Command-Q. Actions run
synchronously; a cached scan can take several seconds.

The bundle is ad-hoc signed for local use, not Developer ID signed or notarized
for public distribution. Do not disable Gatekeeper to run downloaded copies.

## Native functionality

| Feature | Current implementation |
| --- | --- |
| Interface inventory and current connection | macOS `networksetup`, `ifconfig`, `system_profiler` |
| Network metadata | Associated and cached neighboring networks reported by `system_profiler`; not a fresh scan |
| Saved scans | Profiler, legacy airport tables, and row-list imports |
| Sessions and JSON reports | Local files; no cloud or remote host |
| Managed-interface packet capture | Bounded `tcpdump` capture, requires root/BPF access |
| Offline analysis | Optional `aircrack-ng`, `hashcat`, `hcxpcapngtool` |
| Monitor mode, injection, forced handshake capture, WPS, evil twin | Not implemented in this native build |

Available bands, cached metadata, SSID/BSSID visibility, and capture access
depend on the macOS version, hardware, driver, and privacy permissions. A 6 GHz
radio is not assumed merely from an M-series name. Numeric channels alone are
ambiguous across bands; saved scans should include explicit band information.
No M1–M5 compatibility certification or fresh neighbor-scan capability is claimed.

## CLI

```sh
./bin/macgeddon                  # interactive menu; EOF exits
./bin/macgeddon ifaces
./bin/macgeddon caps
./bin/macgeddon doctor
./bin/macgeddon scan
./bin/macgeddon scan --file tests/fixtures/profiler.txt --save
./bin/macgeddon report --out /tmp/macgeddon-report.json
./bin/macgeddon capture --explain
./bin/macgeddon capture --iface en0 --secs 30 --out /tmp/traffic.pcap
```

Without capture privileges the command prints an explicit command to run;
it never launches `sudo` or prompts for credentials. Captures fail if the
output path already exists. Capture durations must be 1–3600 seconds. Managed
captures are ordinary network traffic, not a substitute for monitor capture.

Offline work on capture files you are authorized to analyze:

```sh
brew install aircrack-ng hashcat hcxtools
./bin/macgeddon crack --cap own-network.pcap --wordlist words.txt
./bin/macgeddon crack --convert own-network.pcapng --out own-network.22000
./bin/macgeddon crack --hash own-network.22000 --wordlist words.txt
```

These optional tools are not bundled or installed automatically. Hashcat
backend availability depends on its installed build. Tool errors are failures,
not recovered passwords. The native CLI rejects Linux host/deauthentication
options; `src/remote.k` is historical source, not an exposed workflow.

Exit codes: 0 success, 1 offline search exhausted, 2 invalid arguments,
3 operational failure. `NO_COLOR=1` disables ANSI output; the GUI sets it.

State defaults to `~/.macgeddon`, override with `MACGEDDON_HOME`:

```text
sessions/last.json
sessions/targets.txt
captures/
reports/
```

New state directories are private. Sessions and tool logs can contain sensitive
network information. Legacy comma-list record storage normalizes commas in
SSID metadata to spaces; it is not a lossless SSID archive.

Use only on networks and capture files you own or are authorized to test.
Licensed GPL-3.0; see LICENSE.

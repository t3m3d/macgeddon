#!/usr/bin/env kr
// src/macgeddon.ks — macgeddon: an airgeddon port for macOS on Apple Silicon.
//
// Same shape as airgeddon's main menu (pick interface -> recon -> target ->
// capture -> crack), but the capture column is gated: macOS exposes no
// monitor mode or frame injection, so this build does recon, offline
// cracking and reporting, and explains the rest instead of faking it.
//
// Usage: macgeddon [command] [options]
//   status | caps | ifaces | scan | capture | crack | report | doctor | menu
//
// Build: ../scripts/build.sh   (compiles util/model/platform/wifi/scan/
// capture/crack/report + this file as one translation unit)

module macgeddon

// CLI validation runs before any file, shell, or radio action.
func cliError(message) {
    printErr("macgeddon: " + message)
    exit(2)
}

func optionIn(list, value) {
    for item in list { if item == value { emit "1" } }
    emit "0"
}

func positiveCount(value, limit) {
    if value == "" || len(value) > 6 { emit "0" }
    let i = 0
    while i < len(value) {
        let c = codeAt(value, i)
        if c < 48 || c > 57 { emit "0" }
        i += 1
    }
    if toInt(value) < 1 || toInt(value) > limit { emit "0" }
    emit "1"
}

func validateArgs() {
    if argCount() == 0 { emit "0" }
    let command = arg(0)
    let flags = ""
    let values = ""
    if command == "scan" { flags = "--save" values = "--file,--iface" }
    else if command == "capture" { flags = "--explain,--monitor" values = "--iface,--out,--secs,--count" }
    else if command == "crack" { values = "--cap,--hash,--wordlist,--mask,--bssid,--convert,--out" }
    else if command == "report" { values = "--out" }
    else if optionIn("status,caps,ifaces,doctor,menu,help,--help,-h,version,--version", command) != "1" {
        cliError("unknown command: " + command)
    }
    let i = 1
    while i < argCount() {
        let raw = arg(i)
        let name = raw
        let value = ""
        let eq = indexOf(raw, "=")
        if eq >= 0 { name = substring(raw, 0, eq) value = substring(raw, eq + 1, len(raw)) }
        if optionIn(flags, name) == "1" {
            if eq >= 0 { cliError("flag takes no value: " + name) }
        } else if optionIn(values, name) == "1" {
            if eq < 0 {
                i += 1
                if i >= argCount() { cliError("missing value for " + name) }
                value = arg(i)
            }
            if value == "" || startsWith(value, "--") { cliError("missing value for " + name) }
            if name == "--secs" || name == "--count" {
                if positiveCount(value, 3600) != "1" { cliError(name + " must be an integer from 1 to 3600") }
            }
        } else { cliError("unsupported option for " + command + ": " + name) }
        i += 1
    }
    emit "0"
}

// ── argument helpers ──────────────────────────────────────────────────

func argAt(i) {
    if i < argCount() { emit arg(i) }
    emit ""
}

func hasFlag(name) {
    let i = 0
    while i < argCount() {
        if arg(i) == name { emit "1" }
        i += 1
    }
    emit "0"
}

func optValue(name, dflt) {
    let i = 0
    while i < argCount() {
        if arg(i) == name {
            if i + 1 < argCount() { emit arg(i + 1) }
            emit dflt
        }
        // startsWith returns a boolean and is used directly: comparing it
        // to "1" is always false, which silently killed this branch.
        let pfx = name + "="
        if startsWith(arg(i), pfx) {
            emit substring(arg(i), len(pfx), len(arg(i)))
        }
        i += 1
    }
    emit dflt
}

func optDev() {
    let d = optValue("--iface", "")
    if d != "" { emit d }
    emit wifiIface()
}

// ── help / version ────────────────────────────────────────────────────

func version() { emit "0.1.0" }

func help() {
    banner("macgeddon " + version() + " — airgeddon for macOS / Apple Silicon", 82)
    print("")
    print("  " + colorBold("usage") + "  macgeddon [command] [options]")
    print("")
    print("  " + colorBold("recon"))
    print("    status                 interface, current network, radio verdict")
    print("    caps                   full capability matrix")
    print("    ifaces                 hardware port table")
    print("    scan                   read the associated network (system_profiler)")
    print("    scan --file FILE       parse a saved scan (row list / airport / profiler)")
    print("    scan --save            store parsed targets in the session")
    print("")
    print("  " + colorBold("capture"))
    print("    capture --explain      why monitor mode is unavailable on this Mac")
    print("    capture --secs N       BPF capture on the managed interface")
    print("    capture --monitor      one honest monitor-mode attempt")
    print("")
    print("  " + colorBold("offline work (fully functional)"))
    print("    crack --cap FILE --wordlist FILE [--bssid MAC]")
    print("    crack --hash FILE --wordlist FILE [--mask MASK]")
    print("    crack --convert FILE   pcap/pcapng -> hashcat 22000 (needs hcxtools)")
    print("    report [--out FILE]    write a session report (default reports/)")
    print("    doctor                 toolchain status + install hints")
    print("")
    print("  " + colorBold("other"))
    print("    menu                   interactive menu (airgeddon style)")
    print("    version | help")
    print("")
    print(colorDim("  capabilities are probed, never assumed. nothing here claims a capture"))
    print(colorDim("  that the radio cannot deliver."))
    print("")
}

// ── recon commands ────────────────────────────────────────────────────

func cmdStatus() {
    banner("macgeddon " + version(), 78)
    print("")
    hostLine()
    print("")
    let dev = printInterfaces()
    if dev == "" { emit "3" }
    let v = monitorVerdict()
    print("  " + colorBold("radio   ") + substring(v, indexOf(v, ":") + 1, len(v)))
    print("")
    capRender(capRec("offline cracking ready", minimal(), "aircrack-ng / hashcat on PATH"))
    print("")
    emit "0"
}

func cmdCaps() {
    printMatrix(wifiRadioCap())
    print("")
    emit "0"
}

func cmdIfaces() {
    printInterfaces()
    emit "0"
}

func cmdScan() {
    let file = optValue("--file", "")
    banner("scan", 78)
    print("")
    let dev = optDev()
    let aps = ""
    if file != "" {
        if isFile(file) == "0" {
            bad("no such file: " + file)
            emit "3"
        }
        info("parsing " + file)
        aps = parseAPs(readFile(file))
    } else {
        if dev == "" {
            bad("no Wi-Fi interface found")
            emit "3"
        }
        aps = scanNow(dev)
    }
    aps = dedupe(aps)
    aps = sortByRssi(aps)
    print("")
    if printTable(aps) == "0" { emit "0" }
    if hasFlag("--save") == "1" {
        let p = saveTargetsSession(dev, aps)
        okRow("session saved: " + p)
    } else {
        print("  " + colorDim("add --save to keep these targets in the session"))
    }
    print("")
    emit "0"
}

// ── capture commands ──────────────────────────────────────────────────

func cmdCapture() {
    if hasFlag("--explain") == "1" { explain() emit "0" }
    let dev = optDev()
    if dev == "" { bad("no Wi-Fi interface found") emit "3" }
    if hasFlag("--monitor") == "1" {
        explain()
        bad("monitor capture is not supported by this native build")
        emit "3"
    }
    preflight(dev)
    let out = optValue("--out", defaultCaptureName())
    if managedCapture(dev, out, optValue("--secs", "30")) == "" { emit "3" }
    emit "0"
}

// ── offline commands ──────────────────────────────────────────────────

func cmdCrack() {
    banner("offline cracking", 78)
    print("")
    let logdir = sessDir()
    let convert = optValue("--convert", "")
    if convert != "" {
        let dst = optValue("--out", convert + ".22000")
        if convertTo22000(convert, dst) == "" { emit "3" }
        print("")
        emit "0"
    }
    let hash = optValue("--hash", "")
    let cap = optValue("--cap", "")
    let wl = optValue("--wordlist", "")
    if wl == "" {
        let found = defaultWordlists()
        if lstCount(found) > 0 { wl = lstGet(found, 0) }
    }
    if hash == "" && cap == "" {
        bad("nothing to crack — pass --cap FILE or --hash FILE")
        print("")
        doctor()
        emit "2"
    }
    if wl == "" && optValue("--mask", "") == "" {
        bad("no wordlist — pass --wordlist FILE")
        print("")
        doctor()
        emit "2"
    }
    info("wordlist: " + wl)
    print("")
    let res = ""
    if hash != "" {
        res = crackHash(hash, wl, optValue("--mask", ""), logdir)
    } else {
        res = crackWith(cap, wl, optValue("--bssid", ""), logdir)
    }
    let state = recField(res, 0)
    let key = recField(res, 1)
    let log = recField(res, 2)
    print("")
    if state == "cracked" {
        okRow("KEY FOUND: " + colorBold(colorGreen(key)))
        print("  " + colorDim("log: " + log))
    } else if state == "exhausted" {
        warn(key)
        print("  " + colorDim("log: " + log))
    } else {
        bad(key)
        print("")
        doctor()
        emit "3"
    }
    print("")
    if state == "exhausted" { emit "1" }
    emit "0"
}

func cmdReport() {
    let out = optValue("--out", defaultReportName())
    printSession()
    writeReport(out)
    print("")
    emit "0"
}

func cmdDoctor() {
    doctor()
    emit "0"
}

// ── menu ──────────────────────────────────────────────────────────────

func menu() {
    let dev = wifiIface()
    banner("macgeddon " + version() + " — airgeddon for macOS", 78)
    print("")
    print("  " + colorGray("interface: ") + dev + "   " + colorGray("radio: ") + substring(monitorVerdict(), indexOf(monitorVerdict(), ":") + 1, len(monitorVerdict())))
    print("")
    while 1 == 1 {
        print(colorBold("  1)") + " interface + current network      " + colorBold("6)") + " capture (gated)")
        print(colorBold("  2)") + " capability matrix                " + colorBold("7)") + " offline cracking")
        print(colorBold("  3)") + " scan (associated / file)         " + colorBold("8)") + " session report")
        print(colorBold("  4)") + " targets in session               " + colorBold("9)") + " tool doctor")
        print(colorBold("  5)") + " why capture is gated             " + colorBold("0)") + " exit")
        print("")
        let choice = readLine("macgeddon> ")
        print("")
        if choice == "0" || choice == "q" || choice == "exit" { print("bye.") emit "0" }
        if choice == "" { print(colorDim("no input — exiting")) emit "0" }
        if choice == "1" { printInterfaces() }
        if choice == "2" { printMatrix(wifiRadioCap()) }
        if choice == "3" {
            let aps = dedupe(sortByRssi(scanNow(dev)))
            print("")
            if printTable(aps) == "1" {
                let p = saveTargetsSession(dev, aps)
                okRow("session saved: " + p)
            }
        }
        if choice == "4" {
            let t = loadTargets(targetsPath())
            print("")
            printTable(t)
            printSummary(t)
        }
        if choice == "5" { explain() }
        if choice == "6" {
            preflight(dev)
            print("  Use capture --secs N from the terminal for managed-interface capture.")
        }
        if choice == "7" {
            let wl = defaultWordlists()
            let first = ""
            if lstCount(wl) > 0 { first = lstGet(wl, 0) }
            let cap = readLine("capture file (pcap/pcapng): ")
            let w = readLine("wordlist [" + first + "]: ")
            if w == "" { w = first }
            print("")
            let res = crackWith(cap, w, "", sessDir())
            if recField(res, 0) == "cracked" {
                okRow("KEY FOUND: " + colorBold(colorGreen(recField(res, 1))))
            } else {
                warn(recField(res, 1))
            }
        }
        if choice == "8" { printSession() }
        if choice == "9" { doctor() }
        print("")
    }
    emit "0"
}

// ── entry ─────────────────────────────────────────────────────────────

func main() {
    validateArgs()
    let cmd = argAt(0)
    if cmd == "" { menu() emit "0" }
    if cmd == "help" || cmd == "--help" || cmd == "-h" { help() emit "0" }
    if cmd == "version" || cmd == "--version" { print("macgeddon " + version()) emit "0" }
    if cmd == "status"  { emit cmdStatus() }
    if cmd == "caps"    { emit cmdCaps() }
    if cmd == "ifaces"  { emit cmdIfaces() }
    if cmd == "scan"    { emit cmdScan() }
    if cmd == "capture" { emit cmdCapture() }
    if cmd == "crack"   { emit cmdCrack() }
    if cmd == "report"  { emit cmdReport() }
    if cmd == "doctor"  { emit cmdDoctor() }
    if cmd == "menu"    { menu()       emit "0" }
    bad("unknown command: " + cmd)
    print("")
    help()
    emit "0"
}

just run {
    exit(toInt(main()))
}

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
    print("    scan --host HOST       airodump-ng scan on a Linux capture host")
    print("    scan --save            store parsed targets in the session")
    print("")
    print("  " + colorBold("capture"))
    print("    capture --host HOST    airmon-ng + airodump-ng on a Linux host, pulled back")
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
    print("    host --check HOST      verify the airgeddon toolchain on a Linux host")
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
    if dev == "" { emit "0" }
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
    let rhost = optValue("--host", remoteHost())
    if rhost != "" && file == "" {
        aps = remoteScan(rhost, optValue("--port", remotePort()), optValue("--riface", "wlan0"), optValue("--secs", "20"))
        aps = dedupe(aps)
        aps = sortByRssi(aps)
        print("")
        if printTable(aps) == "0" { emit "0" }
        if hasFlag("--save") == "1" {
            let p = saveTargetsSession(rhost, aps)
            okRow("session saved: " + p)
        }
        print("")
        emit "0"
    }
    if file != "" {
        if isFile(file) == "0" {
            bad("no such file: " + file)
            emit "0"
        }
        info("parsing " + file)
        aps = parseAPs(readFile(file))
    } else {
        if dev == "" {
            bad("no Wi-Fi interface found")
            emit "0"
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
    let dev = optDev()
    if hasFlag("--explain") == "1" { explain() emit "0" }
    if hasFlag("--monitor") == "1" {
        let mout = optValue("--out", capturesDir() + "/mon-" + stamp() + ".pcap")
        monitorAttempt(dev, mout, optValue("--count", "32"))
        emit "0"
    }
    let rhost = optValue("--host", remoteHost())
    if rhost != "" {
        let out = optValue("--out", defaultCaptureName())
        remoteCapture(rhost, optValue("--port", remotePort()), optValue("--riface", "wlan0"),
                      optValue("--bssid", ""), optValue("--channel", ""),
                      optValue("--secs", "30"), optValue("--deauth", ""), out)
        emit "0"
    }
    preflight(dev)
    let out = optValue("--out", defaultCaptureName())
    managedCapture(dev, out, optValue("--secs", "30"))
    emit "0"
}

// ── capture host ──────────────────────────────────────────────────────

func cmdHost() {
    let host = optValue("--host", remoteHost())
    if host == "" {
        banner("capture host", 78)
        print("")
        bad("no host given")
        print("")
        print("    macgeddon host --check user@linux-box")
        print("    MACGEDDON_HOST=user@linux-box macgeddon scan")
        print("")
        emit "0"
    }
    remoteCheck(host, optValue("--port", remotePort()))
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
        convertTo22000(convert, dst)
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
        emit "0"
    }
    if wl == "" {
        bad("no wordlist — pass --wordlist FILE")
        print("")
        doctor()
        emit "0"
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
    }
    print("")
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
            let rhost = remoteHost()
            if rhost != "" {
                remoteCapture(rhost, remotePort(), optValue("--riface", "wlan0"), "", "", "30", "", defaultCaptureName())
            } else {
                preflight(dev)
                print(colorDim("  set MACGEDDON_HOST=user@linux-box to capture on a Linux host"))
                print("")
            }
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
    let cmd = argAt(0)
    if cmd == "" { menu() emit "0" }
    if cmd == "help" || cmd == "--help" || cmd == "-h" { help() emit "0" }
    if cmd == "version" || cmd == "--version" { print("macgeddon " + version()) emit "0" }
    if cmd == "status"  { cmdStatus()  emit "0" }
    if cmd == "caps"    { cmdCaps()    emit "0" }
    if cmd == "ifaces"  { cmdIfaces()  emit "0" }
    if cmd == "scan"    { cmdScan()    emit "0" }
    if cmd == "capture" { cmdCapture() emit "0" }
    if cmd == "crack"   { cmdCrack()   emit "0" }
    if cmd == "report"  { cmdReport()  emit "0" }
    if cmd == "host"    { cmdHost()    emit "0" }
    if cmd == "doctor"  { cmdDoctor()  emit "0" }
    if cmd == "menu"    { menu()       emit "0" }
    bad("unknown command: " + cmd)
    print("")
    help()
    emit "0"
}

just run {
    main()
}

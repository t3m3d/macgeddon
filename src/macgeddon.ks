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
        let pfx = name + "="
        if startsWith(arg(i), pfx) == "1" {
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
    kp("")
    kp("  " + colorBold("usage") + "  macgeddon [command] [options]")
    kp("")
    kp("  " + colorBold("recon"))
    kp("    status                 interface, current network, radio verdict")
    kp("    caps                   full capability matrix")
    kp("    ifaces                 hardware port table")
    kp("    scan                   read the associated network (system_profiler)")
    kp("    scan --file FILE       parse a saved scan (row list / airport / profiler)")
    kp("    scan --host HOST       airodump-ng scan on a Linux capture host")
    kp("    scan --save            store parsed targets in the session")
    kp("")
    kp("  " + colorBold("capture"))
    kp("    capture --host HOST    airmon-ng + airodump-ng on a Linux host, pulled back")
    kp("    capture --explain      why monitor mode is unavailable on this Mac")
    kp("    capture --secs N       BPF capture on the managed interface")
    kp("    capture --monitor      one honest monitor-mode attempt")
    kp("")
    kp("  " + colorBold("offline work (fully functional)"))
    kp("    crack --cap FILE --wordlist FILE [--bssid MAC]")
    kp("    crack --hash FILE --wordlist FILE [--mask MASK]")
    kp("    crack --convert FILE   pcap/pcapng -> hashcat 22000 (needs hcxtools)")
    kp("    report [--out FILE]    write a session report (default reports/)")
    kp("    doctor                 toolchain status + install hints")
    kp("")
    kp("  " + colorBold("other"))
    kp("    host --check HOST      verify the airgeddon toolchain on a Linux host")
    kp("    menu                   interactive menu (airgeddon style)")
    kp("    version | help")
    kp("")
    kp(colorDim("  capabilities are probed, never assumed. nothing here claims a capture"))
    kp(colorDim("  that the radio cannot deliver."))
    kp("")
}

// ── recon commands ────────────────────────────────────────────────────

func cmdStatus() {
    banner("macgeddon " + version(), 78)
    kp("")
    hostLine()
    kp("")
    let dev = printInterfaces()
    if dev == "" { emit "0" }
    let v = monitorVerdict()
    kp("  " + colorBold("radio   ") + substring(v, indexOf(v, ":") + 1, len(v)))
    kp("")
    capRender(capRec("offline cracking ready", minimal(), "aircrack-ng / hashcat on PATH"))
    kp("")
    emit "0"
}

func cmdCaps() {
    printMatrix(wifiRadioCap())
    kp("")
    emit "0"
}

func cmdIfaces() {
    printInterfaces()
    emit "0"
}

func cmdScan() {
    let file = optValue("--file", "")
    banner("scan", 78)
    kp("")
    let dev = optDev()
    let aps = ""
    let rhost = optValue("--host", remoteHost())
    if rhost != "" && file == "" {
        aps = remoteScan(rhost, optValue("--port", remotePort()), optValue("--riface", "wlan0"), optValue("--secs", "20"))
        aps = dedupe(aps)
        aps = sortByRssi(aps)
        kp("")
        if printTable(aps) == "0" { emit "0" }
        if hasFlag("--save") == "1" {
            let p = saveTargetsSession(rhost, aps)
            okRow("session saved: " + p)
        }
        kp("")
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
    kp("")
    if printTable(aps) == "0" { emit "0" }
    if hasFlag("--save") == "1" {
        let p = saveTargetsSession(dev, aps)
        okRow("session saved: " + p)
    } else {
        kp("  " + colorDim("add --save to keep these targets in the session"))
    }
    kp("")
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
        kp("")
        bad("no host given")
        kp("")
        kp("    macgeddon host --check user@linux-box")
        kp("    MACGEDDON_HOST=user@linux-box macgeddon scan")
        kp("")
        emit "0"
    }
    remoteCheck(host, optValue("--port", remotePort()))
    emit "0"
}

// ── offline commands ──────────────────────────────────────────────────

func cmdCrack() {
    banner("offline cracking", 78)
    kp("")
    let logdir = sessDir()
    let convert = optValue("--convert", "")
    if convert != "" {
        let dst = optValue("--out", convert + ".22000")
        convertTo22000(convert, dst)
        kp("")
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
        kp("")
        doctor()
        emit "0"
    }
    if wl == "" {
        bad("no wordlist — pass --wordlist FILE")
        kp("")
        doctor()
        emit "0"
    }
    info("wordlist: " + wl)
    kp("")
    let res = ""
    if hash != "" {
        res = crackHash(hash, wl, optValue("--mask", ""), logdir)
    } else {
        res = crackWith(cap, wl, optValue("--bssid", ""), logdir)
    }
    let state = recField(res, 0)
    let key = recField(res, 1)
    let log = recField(res, 2)
    kp("")
    if state == "cracked" {
        okRow("KEY FOUND: " + colorBold(colorGreen(key)))
        kp("  " + colorDim("log: " + log))
    } else if state == "exhausted" {
        warn(key)
        kp("  " + colorDim("log: " + log))
    } else {
        bad(key)
        kp("")
        doctor()
    }
    kp("")
    emit "0"
}

func cmdReport() {
    let out = optValue("--out", defaultReportName())
    printSession()
    writeReport(out)
    kp("")
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
    kp("")
    kp("  " + colorGray("interface: ") + dev + "   " + colorGray("radio: ") + substring(monitorVerdict(), indexOf(monitorVerdict(), ":") + 1, len(monitorVerdict())))
    kp("")
    while 1 == 1 {
        kp(colorBold("  1)") + " interface + current network      " + colorBold("6)") + " capture (gated)")
        kp(colorBold("  2)") + " capability matrix                " + colorBold("7)") + " offline cracking")
        kp(colorBold("  3)") + " scan (associated / file)         " + colorBold("8)") + " session report")
        kp(colorBold("  4)") + " targets in session               " + colorBold("9)") + " tool doctor")
        kp(colorBold("  5)") + " why capture is gated             " + colorBold("0)") + " exit")
        kp("")
        let choice = readLine("macgeddon> ")
        kp("")
        if choice == "0" || choice == "q" || choice == "exit" { kp("bye.") emit "0" }
        if choice == "" { kp(colorDim("no input — exiting")) emit "0" }
        if choice == "1" { printInterfaces() }
        if choice == "2" { printMatrix(wifiRadioCap()) }
        if choice == "3" {
            let aps = dedupe(sortByRssi(scanNow(dev)))
            kp("")
            if printTable(aps) == "1" {
                let p = saveTargetsSession(dev, aps)
                okRow("session saved: " + p)
            }
        }
        if choice == "4" {
            let t = loadTargets(targetsPath())
            kp("")
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
                kp(colorDim("  set MACGEDDON_HOST=user@linux-box to capture on a Linux host"))
                kp("")
            }
        }
        if choice == "7" {
            let wl = defaultWordlists()
            let first = ""
            if lstCount(wl) > 0 { first = lstGet(wl, 0) }
            let cap = readLine("capture file (pcap/pcapng): ")
            let w = readLine("wordlist [" + first + "]: ")
            if w == "" { w = first }
            kp("")
            let res = crackWith(cap, w, "", sessDir())
            if recField(res, 0) == "cracked" {
                okRow("KEY FOUND: " + colorBold(colorGreen(recField(res, 1))))
            } else {
                warn(recField(res, 1))
            }
        }
        if choice == "8" { printSession() }
        if choice == "9" { doctor() }
        kp("")
    }
    emit "0"
}

// ── entry ─────────────────────────────────────────────────────────────

func main() {
    let cmd = argAt(0)
    if cmd == "" { menu() emit "0" }
    if cmd == "help" || cmd == "--help" || cmd == "-h" { help() emit "0" }
    if cmd == "version" || cmd == "--version" { kp("macgeddon " + version()) emit "0" }
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
    kp("")
    help()
    emit "0"
}

just run {
    main()
}

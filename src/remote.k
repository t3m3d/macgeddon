// src/remote.k — Airgeddon's own capture toolchain, run where it works.
//
// The capture half of airgeddon needs Linux: monitor mode, frame injection
// and airmon-ng / airodump-ng / aireplay-ng. macOS cannot host that, so
// macgeddon drives a Linux capture host over SSH, pulls the artefacts back,
// and cracks them locally with the same aircrack-ng / hashcat it already
// uses. No tool is silently swapped for a pretend one: every remote command
// is printed before it runs, and nothing runs without an explicit host.

module remote

// ── host selection ────────────────────────────────────────────────────

// remoteHost(): default host from the environment, "" when unset.
func remoteHost() {
    emit chomp(exec("printenv MACGEDDON_HOST"))
}

func remotePort() {
    let p = chomp(exec("printenv MACGEDDON_PORT"))
    if p == "" { emit "22" }
    emit p
}

// ── transport ─────────────────────────────────────────────────────────

// sshBase: BatchMode fails fast on a missing key instead of prompting into a
// non-interactive shell; accept-new trusts a first-seen host key only.
func sshBase(host, port) {
    let b = "ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new"
    if port != "" { b = b + " -p " + port }
    emit b + " " + qq(host)
}

func scpBase(port) {
    let b = "scp -q -o BatchMode=yes -o ConnectTimeout=6"
    if port != "" { b = b + " -P " + port }
    emit b
}

// ── capability probe ──────────────────────────────────────────────────

// remoteProbeCmd: one round-trip, no shell variables or quotes so the
// command survives both shells unchanged.
func remoteProbeCmd(host, port) {
    let s = ""
    for t in "airmon-ng,airodump-ng,aireplay-ng,hcxdumptool,iw,timeout" {
        s = s + "command -v " + t + " >/dev/null 2>&1 && echo " + t + "=1 || echo " + t + "=0; "
    }
    s = s + "sudo -n true >/dev/null 2>&1 && echo sudonopass=1 || echo sudonopass=0; "
    s = s + "uname -s"
    emit sshBase(host, port) + " " + qq(s)
}

func remoteProbe(host, port) {
    emit chomp(exec(remoteProbeCmd(host, port)))
}

func remoteHas(out, name) {
    if indexOf(out, name + "=1") >= 0 { emit "1" }
    emit "0"
}

// remoteReady: the three tools airgeddon's capture loop actually needs.
func remoteReady(host, port) {
    let out = remoteProbe(host, port)
    if remoteHas(out, "airmon-ng") == "0" { emit "0" }
    if remoteHas(out, "airodump-ng") == "0" { emit "0" }
    if remoteHas(out, "aireplay-ng") == "0" { emit "0" }
    emit "1"
}

func remoteCaps(host, port) {
    let out = remoteProbe(host, port)
    let caps = ""
    for t in "airmon-ng,airodump-ng,aireplay-ng,hcxdumptool,iw,timeout" {
        let state = "no"
        let detail = "missing on " + host
        if remoteHas(out, t) == "1" {
            state = "yes"
            detail = "found on " + host
        }
        caps = lstAdd(caps, capRec(t, state, detail))
    }
    if indexOf(out, "sudonopass=1") >= 0 {
        caps = lstAdd(caps, capRec("passwordless sudo", "yes", "unattended capture possible"))
    } else {
        caps = lstAdd(caps, capRec("passwordless sudo", "no", "run the printed sudo command on the host"))
    }
    emit caps
}

// ── command builders (pure, unit-tested) ──────────────────────────────

func remoteMonitorCmd(host, port, iface) {
    emit sshBase(host, port) + " " + qq("sudo -n airmon-ng start " + iface)
}

// remoteDumpCmd: timeout(1) bounds the capture on the host so an interrupted
// Mac cannot leave airodump-ng running there.
func remoteDumpCmd(host, port, mon, bssid, channel, secs, base) {
    let inner = "sudo -n timeout " + secs + " airodump-ng"
    if bssid != "" { inner = inner + " --bssid " + bssid }
    if channel != "" { inner = inner + " -c " + channel }
    inner = inner + " -w " + base + " --output-format pcap " + mon
    emit sshBase(host, port) + " " + qq(inner + " >/dev/null 2>&1")
}

func remoteDeauthCmd(host, port, mon, bssid, count) {
    emit sshBase(host, port) + " " + qq("sudo -n aireplay-ng --deauth " + count + " -a " + bssid + " " + mon)
}

func remoteDeauthBgCmd(host, port, mon, bssid, count) {
    let inner = "sudo -n aireplay-ng --deauth " + count + " -a " + bssid + " " + mon + " >/dev/null 2>&1 &"
    emit sshBase(host, port) + " " + qq(inner)
}

func remoteStopMonCmd(host, port, mon) {
    emit sshBase(host, port) + " " + qq("sudo -n airmon-ng stop " + mon)
}

func remotePullCmd(port, host, remotePath, localPath) {
    emit scpBase(port) + " " + qq(host + ":" + remotePath) + " " + qq(localPath)
}

func remoteScanCmd(host, port, mon, secs, base) {
    let inner = "sudo -n timeout " + secs + " airodump-ng -w " + base + " --output-format csv " + mon
    emit sshBase(host, port) + " " + qq(inner + " >/dev/null 2>&1")
}

func remoteBase() { emit "/tmp/macgeddon-" + stamp() }

// parseMonitorName: airmon-ng prints "(monitor mode enabled on wlan0mon)".
func parseMonitorName(out) {
    let marker = "monitor mode enabled on "
    let i = indexOf(out, marker)
    if i < 0 { emit "" }
    let rest = substring(out, i + len(marker), len(out))
    let close = indexOf(rest, ")")
    if close > 0 { emit trimWS(substring(rest, 0, close)) }
    emit trimWS(rest)
}

// ── airodump-ng CSV ───────────────────────────────────────────────────

// csvField(line, want): field at index; "" when the line is short.
func csvField(line, want) {
    let idx = 0
    let start = 0
    let i = 0
    let n = len(line)
    while i <= n {
        let atEnd = i == n
        let comma = 0
        if atEnd == 0 { if codeAt(line, i) == 44 { comma = 1 } }
        if comma == 1 || atEnd == 1 {
            if idx == want { emit trimWS(substring(line, start, i)) }
            idx += 1
            start = i + 1
        }
        i += 1
    }
    emit ""
}

// csvESSID: airodump does not quote, so an SSID may contain commas. The ESSID
// is everything after the 13th comma, minus the trailing Key field.
func csvESSID(line) {
    let commas = 0
    let start = 0
    let i = 0
    let n = len(line)
    while i < n {
        if codeAt(line, i) == 44 {
            commas += 1
            if commas == 13 { start = i + 1 }
        }
        i += 1
    }
    if start == 0 { emit "" }
    let rest = substring(line, start, n)
    let last = 0
    i = 0
    while i < len(rest) {
        if codeAt(rest, i) == 44 { last = i }
        i += 1
    }
    if last > 0 { emit trimWS(substring(rest, 0, last)) }
    emit trimWS(rest)
}

// parseAirodumpCSV(text): APs from airodump-ng's CSV. The file is comma
// separated, so the lines are scanned by hand here: textLines() turns commas
// into spaces (they are Krypton's list separator) and would leave csvField()
// with nothing to split on.
func parseAirodumpCSV(text) {
    let out = ""
    let inStations = 0
    let start = 0
    let i = 0
    let n = len(text)
    while i <= n {
        let atEnd = i == n
        let nl = 0
        if atEnd == 0 {
            let c = codeAt(text, i)
            if c == 10 || c == 13 { nl = 1 }
        }
        if nl == 1 || atEnd == 1 {
            let t = trimWS(substring(text, start, i))
            if indexOf(t, "Station MAC") >= 0 { inStations = 1 }
            if inStations == 0 {
                if looksMac(csvField(t, 0)) == "1" {
                    let ch = csvField(t, 3)
                    let rssi = csvField(t, 8)
                    let sec = securityOf(csvField(t, 5))
                    out = lstAdd(out, apRec(AP {
                        ssid: cleanField(csvESSID(t)),
                        bssid: csvField(t, 0),
                        channel: ch,
                        band: bandOf(ch),
                        rssi: rssi,
                        security: sec,
                        phy: ""
                    }))
                }
            }
            start = i + 1
        }
        i += 1
    }
    emit out
}

// ── orchestration ─────────────────────────────────────────────────────

func remoteCheck(host, port) {
    banner("capture host", 78)
    kp("")
    kp("  " + colorBold("host    ") + host + ":" + port)
    kp("")
    capsRender(remoteCaps(host, port))
    kp("")
    if remoteReady(host, port) == "1" {
        okRow("airgeddon capture toolchain present on the host")
    } else {
        warn("host is missing part of the airgeddon capture toolchain")
        kp("")
        kp("    " + colorBold("sudo apt install aircrack-ng hcxtools wireless-tools iw"))
    }
    kp("")
    kp(colorDim("  env: MACGEDDON_HOST=user@host  MACGEDDON_PORT=22"))
    kp("")
}

func remoteStartMonitor(host, port, iface) {
    let cmd = remoteMonitorCmd(host, port, iface)
    info("monitor: " + cmd)
    let out = chomp(exec(cmd))
    let mon = parseMonitorName(out)
    if mon == "" {
        bad("could not start monitor mode on " + iface)
        kp(colorDim("  " + out))
    }
    emit mon
}

func remoteCapture(host, port, iface, bssid, channel, secs, deauth, localOut) {
    banner("remote capture — airgeddon toolchain", 78)
    kp("")
    kp("  " + colorBold("host    ") + host + ":" + port)
    kp("  " + colorBold("iface   ") + iface)
    kp("")
    if remoteReady(host, port) == "0" {
        bad("capture host lacks airmon-ng / airodump-ng / aireplay-ng")
        kp("")
        kp("    " + colorBold("sudo apt install aircrack-ng wireless-tools iw"))
        kp("")
        emit "0"
    }
    let mon = remoteStartMonitor(host, port, iface)
    if mon == "" { emit "0" }
    okRow("monitor interface: " + mon)
    if deauth != "" && bssid != "" {
        let d = remoteDeauthBgCmd(host, port, mon, bssid, deauth)
        info("deauth:  " + d)
        exec(d)
    }
    let base = remoteBase()
    let dump = remoteDumpCmd(host, port, mon, bssid, channel, secs, base)
    info("capture: " + dump)
    exec(dump)
    let remoteCap = base + "-01.cap"
    let pull = remotePullCmd(port, host, remoteCap, localOut)
    info("pull:    " + pull)
    exec(pull)
    exec(remoteStopMonCmd(host, port, mon))
    kp("")
    if isFile(localOut) == "0" {
        bad("no capture arrived — the host wrote no " + remoteCap)
        kp("")
        emit "0"
    }
    okRow("capture: " + localOut + " (" + fileSize(localOut) + " bytes)")
    kp("")
    kp("  crack it here: " + colorBold("macgeddon crack --cap " + localOut + " --wordlist FILE"))
    kp("")
    emit localOut
}

func remoteScan(host, port, iface, secs) {
    banner("remote scan — airodump-ng", 78)
    kp("")
    if remoteReady(host, port) == "0" {
        bad("capture host lacks airmon-ng / airodump-ng")
        kp("")
        emit ""
    }
    let mon = remoteStartMonitor(host, port, iface)
    if mon == "" { emit "" }
    let base = remoteBase()
    let cmd = remoteScanCmd(host, port, mon, secs, base)
    info("scan:    " + cmd)
    exec(cmd)
    exec(remoteStopMonCmd(host, port, mon))
    let csv = chomp(exec(sshBase(host, port) + " " + qq("cat " + base + "-01.csv")))
    kp("")
    emit parseAirodumpCSV(csv)
}

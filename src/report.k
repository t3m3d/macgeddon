// src/report.k — session state and reports.
//
// Airgeddon keeps session/log directories per run; macgeddon keeps the
// same idea in ~/.macgeddon (override with MACGEDDON_HOME):
//   sessions/last.json   machine-readable session
//   targets.txt          US-joined AP records, one per line
//   captures/            pcap / 22000 / logs
//   reports/             written reports

module report

// ── paths ─────────────────────────────────────────────────────────────

func homeDir() {
    let h = chomp(exec("printenv MACGEDDON_HOME"))
    if h != "" { emit h }
    let home = chomp(exec("printenv HOME"))
    if home == "" { emit "/tmp/macgeddon" }
    emit home + "/.macgeddon"
}

func sessDir()     { ensureDir(homeDir() + "/sessions")  emit homeDir() + "/sessions" }
func capturesDir() { ensureDir(homeDir() + "/captures")  emit homeDir() + "/captures" }
func reportsDir()  { ensureDir(homeDir() + "/reports")   emit homeDir() + "/reports" }
func targetsPath() { emit sessDir() + "/targets.txt" }
func sessionPath() { emit sessDir() + "/last.json" }

func defaultCaptureName() {
    emit capturesDir() + "/cap-" + stamp() + ".pcap"
}

func defaultReportName() {
    emit reportsDir() + "/report-" + stamp() + ".json"
}

// ── JSON fragments ────────────────────────────────────────────────────

func apJSON(r) {
    let a = apFromRec(r)
    emit "{" + jStr("ssid") + ":" + jStr(a.ssid) + "," + jStr("bssid") + ":" + jStr(a.bssid) + "," + jStr("channel") + ":" + jStr(a.channel) + "," + jStr("band") + ":" + jStr(a.band) + "," + jStr("rssi") + ":" + jStr(a.rssi) + "," + jStr("security") + ":" + jStr(a.security) + "," + jStr("phy") + ":" + jStr(a.phy) + "," + jStr("note") + ":" + jStr(apNote(a)) + "}"
}

func targetsJSON(list) {
    let out = "["
    let i = 0
    for r in list {
        if i > 0 { out = out + "," }
        out = out + apJSON(r)
        i += 1
    }
    emit out + "]"
}

func artifactsJSON(list) {
    let out = "["
    let i = 0
    for r in list {
        if i > 0 { out = out + "," }
        out = out + "{" + jStr("kind") + ":" + jStr(recField(r, 0)) + "," + jStr("path") + ":" + jStr(recField(r, 1)) + "," + jStr("note") + ":" + jStr(recField(r, 2)) + "}"
        i += 1
    }
    emit out + "]"
}

// capsJSON: capability matrix as machine-readable rows.
func capsJSON(caps) {
    let out = "["
    let i = 0
    for c in caps {
        if i > 0 { out = out + "," }
        out = out + "{" + jStr("name") + ":" + jStr(capName(c)) + "," + jStr("state") + ":" + jStr(capState(c)) + "," + jStr("detail") + ":" + jStr(capDetail(c)) + "}"
        i += 1
    }
    emit out + "]"
}

// ── summaries ─────────────────────────────────────────────────────────

func countWhere(list, field, value) {
    let n = 0
    for r in list {
        if recField(r, field) == value { n += 1 }
    }
    emit n
}

// bandLabelLong(b): summary form of a band; unknown is named, not rendered
// as "?GHz".
func bandLabelLong(b) {
    if b == "2.4" { emit "2.4GHz" }
    if b == "5"   { emit "5GHz" }
    if b == "6"   { emit "6GHz" }
    emit "unknown"
}

func bandSummary(list) {
    let out = ""
    for b in "2.4,5,6,?" {
        let n = countWhere(list, 3, b)
        if n > 0 { out = lstAdd(out, bandLabelLong(b) + ":" + n) }
    }
    emit out
}

func securitySummary(list) {
    let out = ""
    let seen = ""
    for r in list {
        let s = recField(r, 5)
        if s == "" { s = "unknown" }
        if indexOf("," + seen + ",", "," + s + ",") < 0 {
            seen = lstAdd(seen, s)
            out = lstAdd(out, s + ":" + countWhere(list, 5, s))
        }
    }
    emit out
}

func printSummary(list) {
    if lstCount(list) == 0 {
        warn("no targets in session")
        emit "0"
    }
    print("  " + colorBold("targets   ") + lstCount(list))
    print("  " + colorBold("bands     ") + bandSummary(list))
    print("  " + colorBold("security  ") + securitySummary(list))
    let best = ""
    let bestRssi = -999
    for r in list {
        let rssi = recField(r, 4)
        if rssi != "" {
            if toInt(rssi) > bestRssi {
                bestRssi = toInt(rssi)
                best = r
            }
        }
    }
    if best != "" {
        print("  " + colorBold("strongest ") + recField(best, 0) + " (" + recField(best, 4) + " dBm)")
    } else {
        print("  " + colorBold("strongest ") + colorDim("unknown — no signal values in this scan"))
    }
    emit "1"
}

// ── session file ──────────────────────────────────────────────────────

func writeSession(iface, targets, artifacts, out) {
    ensureDir(sessDir())
    let body = "{" + fromCharCode(10)
    body = body + jPair("tool", "macgeddon") + "," + fromCharCode(10)
    body = body + jPair("version", "0.1.0") + "," + fromCharCode(10)
    body = body + jPair("started", nowISO()) + "," + fromCharCode(10)
    body = body + jPair("host", hostName()) + "," + fromCharCode(10)
    body = body + jPair("arch", arch()) + "," + fromCharCode(10)
    body = body + jPair("chip", chip()) + "," + fromCharCode(10)
    body = body + jPair("interface", iface) + "," + fromCharCode(10)
    body = body + jStr("radio") + ": " + capsJSON(wifiCaps()) + "," + fromCharCode(10)
    body = body + jStr("targets") + ": " + targetsJSON(targets) + "," + fromCharCode(10)
    body = body + jStr("artifacts") + ": " + artifactsJSON(artifacts) + fromCharCode(10)
    body = body + "}" + fromCharCode(10)
    writeFile(out, body)
    emit out
}

func wifiCaps() {
    let caps = ""
    caps = lstAdd(caps, wifiRadioCap())
    caps = lstAdd(caps, capRec("frame injection", "no", "no userland 802.11 transmit path"))
    emit caps
}

func saveTargetsSession(iface, targets) {
    saveTargets(targets, targetsPath())
    let path = writeSession(iface, targets, inventory(capturesDir()), sessionPath())
    emit path
}

// ── reporting ─────────────────────────────────────────────────────────

func printSession() {
    let p = sessionPath()
    banner("session", 78)
    print("")
    if isFile(p) == "0" {
        warn("no session yet — run `macgeddon scan` first")
        print("")
        emit "0"
    }
    print("  " + colorBold("file    ") + p)
    print("  " + colorBold("home    ") + homeDir())
    print("")
    let targets = loadTargets(targetsPath())
    printSummary(targets)
    print("")
    let arts = inventory(capturesDir())
    if lstCount(arts) > 0 {
        print("  " + colorBold("artifacts"))
        for a in arts {
            print("    " + padR(recField(a, 0), 9) + padR(recField(a, 1), 48) + colorGray(recField(a, 2)))
        }
    } else {
        print("  " + colorDim("no captures in " + capturesDir()))
    }
    print("")
    emit "1"
}

func writeReport(out) {
    let iface = wifiIface()
    let targets = loadTargets(targetsPath())
    let path = writeSession(iface, targets, inventory(capturesDir()), out)
    okRow("report written: " + path)
    emit path
}

func listSessions() {
    let out = ""
    for f in listDir(reportsDir()) { out = lstAdd(out, reportsDir() + "/" + f) }
    emit out
}

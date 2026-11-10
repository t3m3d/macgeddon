// src/scan.k — turning text into access-point records.
//
// Three sources are supported, all as text so every parser is testable
// offline against a saved file:
//   * system_profiler SPAirPortDataType   (unprivileged, current network)
//   * any saved row list: SSID MAC RSSI CH SEC (third-party scanners)
//   * `airport -s` legacy table           (pre-14.4 captures)
//
// Lines lose commas on ingest (see util.lines): comma is Krypton's list
// separator, and no value we need from these files depends on one.

module scan

// ── tokenising ────────────────────────────────────────────────────────

// tokens(line): whitespace-run-separated fields as a comma-list.
func tokens(line) {
    let out = ""
    let cur = ""
    let i = 0
    let n = len(line)
    while i <= n {
        let atEnd = i == n
        let isSep = 0
        let c = -1
        if atEnd == 0 { c = codeAt(line, i) }
        if c == 32 || c == 9 { isSep = 1 }
        if isSep == 1 || atEnd == 1 {
            if cur != "" {
                out = lstAdd(out, cur)
                cur = ""
            }
        } else {
            cur = cur + chAt(line, i)
        }
        i += 1
    }
    emit out
}

func looksMac(s) {
    if len(s) != 17 { emit "0" }
    let colons = 0
    let i = 0
    while i < 17 {
        if codeAt(s, i) == 58 { colons += 1 }
        i += 1
    }
    if colons == 5 { emit "1" }
    emit "0"
}

// ── field normalisation ───────────────────────────────────────────────

// channelOf("44 (5GHz, 80MHz)") -> "44"
func channelOf(s) {
    let t = trimWS(s)
    let sp = indexOf(t, " ")
    if sp > 0 { emit substring(t, 0, sp) }
    emit t
}

// rssiOf("-55 dBm / -92 dBm") -> "-55"
func rssiOf(s) {
    let t = trimWS(s)
    let sp = indexOf(t, " ")
    if sp > 0 { emit substring(t, 0, sp) }
    emit t
}

// securityOf normalises the many spellings macOS uses.
func securityOf(s) {
    let t = trimWS(s)
    if t == "" || t == "None" || t == "none" || t == "NONE" || t == "OPN" { emit "Open" }
    if indexOf(t, "WPA3") >= 0 && indexOf(t, "WPA2") >= 0 { emit "WPA2/WPA3" }
    if indexOf(t, "WPA3") >= 0 { emit "WPA3" }
    if indexOf(t, "WPA2") >= 0 { emit "WPA2" }
    if indexOf(t, "WPA") >= 0 { emit "WPA" }
    if indexOf(t, "WEP") >= 0 { emit "WEP" }
    if indexOf(t, "OWE") >= 0 { emit "OWE" }
    emit t
}

// ── system_profiler ───────────────────────────────────────────────────

func isSectionLabel(l) {
    if endsWithS(l, ":") == "0" { emit "0" }
    let name = substring(l, 0, len(l) - 1)
    let known = "Wi-Fi|Software Versions|Interfaces|Current Network Information|Other Local Wi-Fi Networks|Supported Channels|Supported PHY Modes|Wake On Wireless|AirDrop|Auto Unlock|Apple Wireless Direct Link|AirPlay|Instant Hotspot|Hardware|Network Preferences|Locale|Country Code|Status|Card Type|Firmware Version|MAC Address|MCS Index|Rate"
    if indexOf("|" + known + "|", "|" + name + "|") >= 0 { emit "1" }
    if startsWith(name, "en") { if len(name) <= 6 { emit "1" } }
    emit "0"
}

func endsWithS(s, suffix) {
    if len(s) < len(suffix) { emit "0" }
    let tail = substring(s, len(s) - len(suffix), len(s))
    if tail == suffix { emit "1" }
    emit "0"
}

// parseAPBlock: one "SSID:" header plus its indented key/value lines.
func parseAPBlock(block) {
    let ls = textLines(block)
    if lstCount(ls) == 0 { emit "" }
    let head = lstGet(ls, 0)
    let ssid = ""
    if endsWithS(head, ":") == "1" { ssid = substring(head, 0, len(head) - 1) }
    let bssid = ""
    let ch = ""
    let sec = ""
    let rssi = ""
    let phy = ""
    let i = 1
    let n = lstCount(ls)
    while i < n {
        let l = lstGet(ls, i)
        let sep = indexOf(l, ": ")
        if sep > 0 {
            let k = substring(l, 0, sep)
            let v = substring(l, sep + 2, len(l))
            if k == "BSSID" { bssid = cleanField(v) }
            if k == "Channel" { ch = channelOf(v) }
            if k == "Security" { sec = securityOf(v) }
            if k == "Signal / Noise" { rssi = rssiOf(v) }
            if k == "PHY Mode" { phy = cleanField(v) }
        }
        i += 1
    }
    emit apRec(AP { ssid: cleanField(ssid), bssid: bssid, channel: ch, band: bandOf(ch), rssi: rssi, security: sec, phy: phy })
}

// isAPRecord(r): a real network carries at least one of BSSID, channel,
// security or PHY mode. Interface blocks such as `awdl0:` also end in a
// colon and look like an SSID header, but hold none of these, so they are
// dropped instead of becoming a phantom target.
func isAPRecord(r) {
    if recField(r, 1) != "" { emit "1" }
    if recField(r, 2) != "" { emit "1" }
    if recField(r, 5) != "" { emit "1" }
    if recField(r, 6) != "" { emit "1" }
    emit "0"
}

func parseProfiler(text) {
    let ls = textLines(text)
    let blocks = ""
    let cur = ""
    let inAP = 0
    for l in ls {
        let isSSID = 0
        if endsWithS(l, ":") == "1" { if isSectionLabel(l) == "0" { isSSID = 1 } }
        if isSSID == 1 {
            if inAP == 1 { blocks = lstAdd(blocks, cur) }
            cur = l
            inAP = 1
        } else if isSectionLabel(l) == "1" {
            if inAP == 1 { blocks = lstAdd(blocks, cur) }
            cur = ""
            inAP = 0
        } else if inAP == 1 {
            cur = cur + fromCharCode(10) + l
        }
    }
    if inAP == 1 { blocks = lstAdd(blocks, cur) }
    let out = ""
    for b in blocks {
        let r = parseAPBlock(b)
        if isAPRecord(r) == "1" { out = lstAdd(out, r) }
    }
    emit out
}

// ── loose rows (row lists / airport / hand-saved captures) ────────────

func parseLoose(text) {
    let out = ""
    for l in textLines(text) {
        let toks = tokens(l)
        let n = lstCount(toks)
        let bssid = ""
        let ssid = ""
        let rssi = ""
        let ch = ""
        let sec = ""
        let i = 0
        while i < n {
            let t = lstGet(toks, i)
            if looksMac(t) == "1" && bssid == "" {
                bssid = t
            } else if startsWith(t, "-") && toInt(t) < 0 && toInt(t) > -120 && rssi == "" {
                rssi = t
            } else if containsC(t, "WPA") == "1" || containsC(t, "WEP") == "1" || containsC(t, "Open") == "1" || containsC(t, "OWE") == "1" {
                sec = securityOf(t)
            } else if bssid == "" && ssid == "" && toInt(t) == 0 && looksMac(t) == "0" {
                ssid = t
            } else if bssid != "" && ch == "" && toInt(t) > 0 && toInt(t) <= 196 {
                ch = t
            }
            i += 1
        }
        if bssid != "" {
            let name = ssid
            if name == "SSID" { name = "" }
            out = lstAdd(out, apRec(AP { ssid: cleanField(name), bssid: bssid, channel: ch, band: bandOf(ch), rssi: rssi, security: sec, phy: "" }))
        }
    }
    emit out
}

func containsC(hay, needle) {
    if indexOf(hay, needle) >= 0 { emit "1" }
    emit "0"
}

// parseAPs: profiler input is parsed only by the profiler parser, so an
// interface block can never leak in through the loose-row fallback.
func parseAPs(text) {
    if indexOf(text, "PHY Mode") >= 0 || indexOf(text, "Current Network Information") >= 0 {
        emit parseProfiler(text)
    }
    let b = parseLoose(text)
    if lstCount(b) > 0 { emit b }
    emit ""
}

// ── ordering / display ────────────────────────────────────────────────

func rssiVal(r) {
    let v = recField(r, 4)
    if v == "" { emit -200 }
    emit toInt(v)
}

// sortByRssi: strongest first (insertion sort; lists here are short).
func sortByRssi(list) {
    let out = ""
    for r in list {
        let v = rssiVal(r)
        let placed = 0
        let next = ""
        for o in out {
            if placed == 0 && v > rssiVal(o) {
                next = lstAdd(next, r)
                placed = 1
            }
            next = lstAdd(next, o)
        }
        if placed == 0 { next = lstAdd(next, r) }
        out = next
    }
    emit out
}

func dedupe(list) {
    let seen = ""
    let out = ""
    for r in list {
        let b = recField(r, 1)
        if b == "" { b = recField(r, 0) }
        if indexOf("," + seen + ",", "," + b + ",") < 0 {
            seen = lstAdd(seen, b)
            out = lstAdd(out, r)
        }
    }
    emit out
}

func printTable(aps) {
    if lstCount(aps) == 0 {
        warn("no access points parsed")
        emit "0"
    }
    print(apHeader())
    let i = 1
    for r in aps {
        let a = apFromRec(r)
        print(colorGray(padL(i, 3) + ") ") + apLine(a))
        i += 1
    }
    print("")
    emit "1"
}

func saveTargets(aps, path) {
    let out = ""
    for r in aps { out = out + r + fromCharCode(10) }
    writeFile(path, out)
    emit path
}

func loadTargets(path) {
    if isFile(path) == "0" { emit "" }
    let out = ""
    for l in textLines(readFile(path)) {
        if recCount(l) >= 7 { out = lstAdd(out, l) }
    }
    emit out
}

// scanNow(): unprivileged live read. system_profiler reports the associated
// network plus the cached neighbour list; macOS has no scan command, so a live
// neighbourhood scan is neither faked nor delegated to a tool that lacks it.
func scanNow(dev) {
    let aps = parseProfiler(profiler(dev))
    if lstCount(aps) > 0 {
        info("source: system_profiler (associated + cached neighbour networks)")
    } else {
        warn("no wireless networks reported for " + dev)
    }
    if isRoot() == "0" {
        print("")
        print(colorDim("  macOS has no neighbour-scan command: airport -s went away in 14.4"))
        print(colorDim("  and wdutil has no scan. For a live scan with signal data, scan on"))
        print(colorDim("  a Linux host, then: macgeddon scan --file scan.txt"))
    }
    emit aps
}

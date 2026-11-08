// src/crack.k — offline WPA work. This is the part of the port that is
// genuinely useful on an Apple Silicon Mac: everything runs on files, so
// a capture made on a Linux box cracks here at full Metal speed.

module crack

// ── artifacts ─────────────────────────────────────────────────────────

func artifactKind(path) {
    if endsWithS(path, ".pcapng") == "1" { emit "pcapng" }
    if endsWithS(path, ".pcap") == "1"   { emit "pcap" }
    if endsWithS(path, ".cap") == "1"    { emit "pcap" }
    if endsWithS(path, ".22000") == "1"  { emit "22000" }
    if endsWithS(path, ".hc22000") == "1" { emit "22000" }
    if endsWithS(path, ".hccapx") == "1" { emit "hccapx" }
    if endsWithS(path, ".txt") == "1"    { emit "wordlist" }
    if endsWithS(path, ".json") == "1"   { emit "report" }
    emit "other"
}

func isCapture(path) {
    let k = artifactKind(path)
    if k == "pcap" || k == "pcapng" || k == "22000" || k == "hccapx" { emit "1" }
    emit "0"
}

// inventory(dir): capture-ish files, newest last.
func inventory(dir) {
    let out = ""
    for f in listDir(dir) {
        let p = dir + "/" + f
        if isCapture(p) == "1" {
            out = lstAdd(out, rec(artifactKind(p) + "," + cleanField(p) + "," + fileSize(p) + " bytes"))
        }
    }
    emit out
}

// ── tool discovery ────────────────────────────────────────────────────

func haveTool(name) {
    if which(name) != "" { emit "1" }
    emit "0"
}

func defaultWordlists() {
    let out = ""
    let cands = "/usr/local/share/wordlists/rockyou.txt,/opt/homebrew/share/wordlists/rockyou.txt,/usr/share/wordlists/rockyou.txt,/usr/share/dict/words"
    for c in cands {
        if isFile(c) == "1" { out = lstAdd(out, c) }
    }
    emit out
}

// brewHint: the exact command a user needs for a missing tool.
// "system" (built in), "host" (Linux capture host only) and "?" (unknown)
// are not brewable, so they are never echoed as install commands.
func brewHint(names) {
    let out = ""
    for n in names {
        if haveTool(n) == "0" {
            let f = toolFormula(n)
            if f != "system" && f != "host" && f != "?" { out = lstAdd(out, f) }
        }
    }
    emit out
}

// ── running tools ─────────────────────────────────────────────────────

// runTool: execute, capture combined output to log, return "rc<TAB>log".
func runTool(cmd, log) {
    let rc = chomp(exec("( " + cmd + " ) >" + qq(log) + " 2>&1; echo RC=$?"))
    rc = replace(rc, "RC=", "")
    emit rec(cleanField(rc) + "," + cleanField(log))
}

// ── conversion ────────────────────────────────────────────────────────

func convertTo22000(src, dst) {
    if haveTool("hcxpcapngtool") == "0" {
        bad("hcxpcapngtool missing (brew install hcxtools)")
        emit ""
    }
    if isFile(src) == "0" {
        bad("no such capture: " + src)
        emit ""
    }
    info("converting " + src + " -> " + dst)
    let r = runTool("hcxpcapngtool -o " + qq(dst) + " " + qq(src), dst + ".log")
    if isFile(dst) == "1" {
        okRow("wrote " + dst + " (" + fileSize(dst) + " bytes)")
        emit dst
    }
    bad("conversion produced no output (see " + dst + ".log)")
    emit ""
}

// ── cracking ──────────────────────────────────────────────────────────

// aircrackCommand: CPU path, no conversion needed.
func aircrackCommand(cap, wordlist, bssid) {
    let cmd = "aircrack-ng -w " + qq(wordlist)
    if bssid != "" { cmd = cmd + " -b " + bssid }
    emit cmd + " " + qq(cap)
}

// hashcatCommand: GPU path; mode 22000 covers PMKID and EAPOL.
func hashcatCommand(hash, wordlist, mask, potfile) {
    let cmd = "hashcat -m 22000 -a 0 --potfile-path " + qq(potfile) + " --quiet "
    if mask != "" { cmd = "hashcat -m 22000 -a 3 --potfile-path " + qq(potfile) + " --quiet " + qq(hash) + " " + qq(mask) }
    if mask != "" { emit cmd }
    emit cmd + qq(hash) + " " + qq(wordlist)
}

func parseAircrack(out) {
    let i = indexOf(out, "KEY FOUND!")
    if i < 0 { emit "" }
    let tail = substring(out, i, len(out))
    let lb = indexOf(tail, "[")
    let rb = indexOf(tail, "]")
    if lb >= 0 && rb > lb { emit trimWS(substring(tail, lb + 1, rb)) }
    emit trimWS(tail)
}

func parseHashcat(out) {
    let ls = textLines(out)
    let last = ""
    for l in ls { last = l }
    if last == "" { emit "" }
    let c = 0
    let i = 0
    while i < len(last) {
        if codeAt(last, i) == 58 { c = i }
        i += 1
    }
    emit substring(last, c + 1, len(last))
}

// crackWith: run aircrack-ng against a pcap, return "<state>,<key>,<log>".
func crackWith(cap, wordlist, bssid, logDir) {
    if isFile(cap) == "0" { emit rec("error," + "no such capture,") }
    if isFile(wordlist) == "0" { emit rec("error," + "no such wordlist,") }
    if haveTool("aircrack-ng") == "0" { emit rec("error," + "aircrack-ng missing,") }
    let log = logDir + "/aircrack.log"
    let cmd = aircrackCommand(cap, wordlist, bssid)
    info("running: " + cmd)
    let r = runTool(cmd, log)
    let out = readFile(log)
    let key = parseAircrack(out)
    if key != "" { emit rec("cracked," + cleanField(key) + "," + cleanField(log)) }
    emit rec("exhausted," + cleanField("key not in " + wordlist) + "," + cleanField(log))
}

// crackHash: hashcat equivalent, for .22000 input.
func crackHash(hash, wordlist, mask, logDir) {
    if isFile(hash) == "0" { emit rec("error," + "no such hash file,") }
    if haveTool("hashcat") == "0" { emit rec("error," + "hashcat missing,") }
    let log = logDir + "/hashcat.log"
    let pot = logDir + "/hashcat.potfile"
    let cmd = hashcatCommand(hash, wordlist, mask, pot)
    if mask == "" && isFile(wordlist) == "0" { emit rec("error," + "no such wordlist,") }
    info("running: " + cmd)
    runTool(cmd, log)
    let out = readFile(log)
    let key = parseHashcat(out)
    if key != "" { emit rec("cracked," + cleanField(key) + "," + cleanField(log)) }
    if isFile(pot) == "1" { emit rec("cracked," + cleanField(readFile(pot)) + "," + cleanField(pot)) }
    emit rec("exhausted," + cleanField("no match in " + wordlist) + "," + cleanField(log))
}

// ── helpers surfaced in the UI ────────────────────────────────────────

// maskHint: a cheap guess at a mask worth trying first.
func maskHint(ssid) {
    if ssid == "" { emit "?d?d?d?d?d?d?d?d" }
    let n = len(ssid)
    if indexOf(ssid, "iPhone") >= 0 || indexOf(ssid, "Android") >= 0 { emit "?d?d?d?d?d?d?d?d" }
    if n == 8 { emit "?d?d?d?d?d?d?d?d" }
    if n >= 8 { emit "?a?a?a?a?a?a?a?a" }
    emit "?a?a?a?a?a?a"
}

func doctor() {
    banner("tool doctor", 78)
    kp("")
    capsRender(toolCaps())
    let missing = brewHint("aircrack-ng,hashcat,hcxpcapngtool,tshark")
    kp("")
    if missing == "" {
        okRow("offline cracking toolchain complete")
    } else {
        warn("missing formulas")
        kp("")
        kp("    " + colorBold("brew install " + replace(missing, ",", " ")))
        kp("")
        kp(colorDim("  hashcat on Apple Silicon uses Metal; no extra driver needed."))
    }
    kp("")
    let wl = defaultWordlists()
    if wl == "" {
        warn("no wordlist found — put rockyou.txt in /usr/local/share/wordlists/")
    } else {
        okRow("wordlists available:")
        for w in wl { kp("      " + w) }
    }
    kp("")
}

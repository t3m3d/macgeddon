// src/platform.k — host, toolchain and permission probes.
//
// Everything here shells out to stock macOS binaries; no third-party
// dependency is required to answer "what can this machine actually do?".
// This module must not call into wifi.k (module order: util, model,
// platform, wifi, scan, ...), so the radio row is rendered by the caller.

module platform

// ── host ──────────────────────────────────────────────────────────────

func osName()    { emit chomp(exec("sw_vers -productName 2>/dev/null")) }
func osVersion() { emit chomp(exec("sw_vers -productVersion 2>/dev/null")) }
func osBuild()   { emit chomp(exec("sw_vers -buildVersion 2>/dev/null")) }
func arch()      { emit chomp(exec("uname -m")) }
func kernel()    { emit chomp(exec("uname -r")) }
func user()      { emit chomp(exec("id -un")) }
func chip()      { emit chomp(exec("sysctl -n machdep.cpu.brand_string 2>/dev/null")) }

func isRoot() {
    if chomp(exec("id -u")) == "0" { emit "1" }
    emit "0"
}

func isAppleSilicon() {
    if arch() == "arm64" { emit "1" }
    emit "0"
}

// ── third-party tools ─────────────────────────────────────────────────

func toolFormula(name) {
    if name == "aircrack-ng"     { emit "aircrack-ng" }
    if name == "hashcat"         { emit "hashcat" }
    if name == "hcxpcapngtool"   { emit "hcxtools" }
    if name == "hcxdumptool"     { emit "hcxdumptool" }
    if name == "tcpdump"         { emit "system" }
    if name == "wdutil"          { emit "system" }
    if name == "networksetup"    { emit "system" }
    if name == "system_profiler" { emit "system" }
    if name == "ssh"             { emit "system" }
    if name == "scp"             { emit "system" }
    emit "?"
}

func toolLabel(name) {
    if name == "aircrack-ng"   { emit "aircrack-ng   offline WPA handshake crack" }
    if name == "hashcat"       { emit "hashcat       GPU crack (Metal on Apple Silicon)" }
    if name == "hcxpcapngtool" { emit "hcxpcapngtool pcap -> hashcat 22000 converter" }
    if name == "hcxdumptool"   { emit "hcxdumptool   PMKID/handshake capture (Linux-centric)" }
    if name == "tcpdump"       { emit "tcpdump       packet capture (BPF)" }
    if name == "wdutil"        { emit "wdutil        Wi-Fi diagnostics" }
    if name == "networksetup"  { emit "networksetup  hardware port inventory" }
    if name == "system_profiler" { emit "system_profiler  attached-network readout" }
    if name == "ssh"           { emit "ssh           remote capture host transport" }
    if name == "scp"           { emit "scp           remote capture pull" }
    emit name
}

func toolRec(name) {
    let path = which(name)
    if path != "" { emit capRec(toolLabel(name), "yes", path) }
    let hint = "brew install " + toolFormula(name)
    if toolFormula(name) == "system" { hint = "not present on this macOS build" }
    emit capRec(toolLabel(name), "no", hint)
}

// ── capability records ("name<US>state<US>detail") ────────────────────

func capRec(name, state, detail) {
    emit rec(cleanField(name) + "," + cleanField(state) + "," + cleanField(detail))
}

func capName(c)   { emit recField(c, 0) }
func capState(c)  { emit recField(c, 1) }
func capDetail(c) { emit recField(c, 2) }

func capRender(c) {
    let state = capState(c)
    let tag = colorGray("[ -- ]")
    if state == "yes" { tag = colorGreen("[ ok ]") }
    if state == "partial" { tag = colorYellow("[part]") }
    if state == "no" { tag = colorRed("[ no ]") }
    kp("  " + tag + " " + padR(capName(c), 54) + colorGray(capDetail(c)))
}

func capsRender(caps) {
    for c in caps { capRender(c) }
}

// ── matrix ────────────────────────────────────────────────────────────

func permissionCaps() {
    let caps = ""
    if isRoot() == "1" {
        caps = lstAdd(caps, capRec("root privileges", "yes", "running as root"))
    } else {
        caps = lstAdd(caps, capRec("root privileges", "no", "capture needs sudo; commands are printed"))
    }
    caps = lstAdd(caps, capRec("Apple Silicon", "yes", chip() + " / " + arch()))
    emit caps
}

func toolCaps() {
    let names = "tcpdump,networksetup,wdutil,system_profiler,ssh,scp,aircrack-ng,hashcat,hcxpcapngtool,hcxdumptool"
    let caps = ""
    for n in names { caps = lstAdd(caps, toolRec(n)) }
    emit caps
}

func allCaps() {
    let caps = permissionCaps()
    for t in toolCaps() { caps = lstAdd(caps, t) }
    emit caps
}

// ── reporting ─────────────────────────────────────────────────────────

func hostLine() {
    kp(colorBold("host   ") + hostName() + "  " + colorGray(user()))
    kp(colorBold("system ") + osName() + " " + osVersion() + " (" + osBuild() + ")  " + chip())
}

func printMatrix(radioCap) {
    banner("macgeddon capability matrix", 82)
    kp("")
    hostLine()
    kp("")
    capRender(radioCap)
    capsRender(allCaps())
    kp("")
    kp(colorDim("  capture and attack features are gated by what macOS exposes"))
    kp(colorDim("  to userland; see README.md and `macgeddon capture --explain`."))
    kp("")
}

func minimal() {
    if which("aircrack-ng") != "" { emit "1" }
    if which("hashcat") != "" { emit "1" }
    emit "0"
}

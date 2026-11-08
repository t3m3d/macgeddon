// src/model.k — data types for macgeddon.
//
// Values are flat strings (Krypton has no typed numerics at the value level),
// so the structs here are records with accessors, not stateful objects.
// Anything that must survive into a session file is serialisable to one
// US-joined record via util.rec().

module model

// Iface: one network device as macOS reports it.
struct Iface {
    let name        // en0
    let port        // "Wi-Fi"
    let mac         // aa:bb:cc:dd:ee:ff
}

// AP: one observed access point.
struct AP {
    let ssid
    let bssid
    let channel
    let band        // 2.4 / 5 / 6
    let rssi        // dBm as a string, "" when unknown
    let security    // WPA3 / WPA2 / WPA / WEP / OWE / Open / ""
    let phy         // 802.11ax, etc.
}

// Cap: one line of the capability matrix.
struct Cap {
    let name
    let state       // yes / no / partial
    let detail
}

// Artifact: a file that a capture or cracking step produced or needs.
struct Artifact {
    let kind        // pcap / pcapng / hccapx / 22000 / wordlist / report
    let path
    let note
}

// Session: everything a run knows, serialised as one record list.
struct Session {
    let iface
    let started
    let host
    let targets     // comma-list of AP records
    let artifacts   // comma-list of Artifact records
}

// ── AP helpers ────────────────────────────────────────────────────────

func bandOf(channel) {
    let ch = channel
    let i = indexOf(ch, " ")
    if i > 0 { ch = substring(ch, 0, i) }
    let n = toInt(ch)
    if n >= 1 && n <= 14 { emit "2.4" }
    if n >= 32 && n <= 196 { emit "5" }
    if n > 196 { emit "6" }
    emit "?"
}

// bandLabel(b): display form of the band field.
func bandLabel(b) {
    if b == "2.4" { emit "2.4G" }
    if b == "5"   { emit "5G" }
    if b == "6"   { emit "6G" }
    emit "?"
}

// apRec(ap): flatten an AP into one US-joined record.
func apRec(ap) {
    emit rec("" + ap.ssid + "," + ap.bssid + "," + ap.channel + "," + ap.band + "," + ap.rssi + "," + ap.security + "," + ap.phy)
}

func apFromRec(r) {
    emit AP {
        ssid: recField(r, 0),
        bssid: recField(r, 1),
        channel: recField(r, 2),
        band: recField(r, 3),
        rssi: recField(r, 4),
        security: recField(r, 5),
        phy: recField(r, 6)
    }
}

// apLine(ap): fixed-width table row for target lists.
func apLine(ap) {
    let ssid = ap.ssid
    if ssid == "" { ssid = "<hidden>" }
    let rssi = ap.rssi
    if rssi == "" { rssi = "?" }
    emit padR(ssid, 28) + padL(ap.channel, 4) + padL(bandLabel(ap.band), 5) + padL(rssi, 7) + "  " + padR(ap.security, 9) + "  " + ap.bssid
}

func apHeader() {
    emit colorBold(padR("SSID", 28) + padL("CH", 4) + padL("BAND", 5) + padL("RSSI", 7) + "  " + padR("SECURITY", 9) + "  BSSID")
    emit colorGray(dash(74))
}

// securityRank: rough ordering for "is this worth attacking" — higher is better.
func securityRank(sec) {
    if startsWith(sec, "WPA3") { emit "1" }
    if startsWith(sec, "WPA2") { emit "3" }
    if startsWith(sec, "WPA") { emit "4" }
    if sec == "OWE"            { emit "2" }
    if sec == "WEP"            { emit "5" }
    if sec == "Open"           { emit "0" }
    emit "0"
}

// apNote: the honest one-liner a macOS user needs about a target.
func apNote(ap) {
    let sec = ap.security
    if sec == "Open" { emit "open network — no handshake to capture" }
    if sec == "WEP" { emit "WEP: legacy, no WPA handshake; capture is enough" }
    if startsWith(sec, "WPA3") { emit "WPA3-SAE: no WPA 4-way capture path on this build" }
    if startsWith(sec, "WPA2") { emit "WPA2-PSK: handshake or PMKID target" }
    if startsWith(sec, "WPA") { emit "WPA-PSK: handshake target" }
    if sec == "OWE" { emit "OWE: encrypted, no PSK to crack" }
    emit "unknown security type"
}

// capRow: "name<TAB>state<TAB>detail" so callers can colour by state.
func capOf(name, state, detail) {
    emit Cap { name: name, state: state, detail: detail }
}

func capLine(cap) {
    let tag = colorGray("[ -- ]")
    if cap.state == "yes" { tag = colorGreen("[ ok ]") }
    if cap.state == "partial" { tag = colorYellow("[part]") }
    if cap.state == "no" { tag = colorRed("[ no ]") }
    emit "  " + tag + " " + padR(cap.name, 20) + cap.detail
}

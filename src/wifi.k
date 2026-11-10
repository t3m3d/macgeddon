// src/wifi.k — interface discovery, current-network readout and the
// honest verdict on monitor mode / injection for this radio.
//
// macOS hands userland no way to put a Wi-Fi radio into monitor mode or to
// inject 802.11 frames. On Apple Silicon that is unconditional: `airport`
// was removed in 14.4, wdutil only reports link state, and the driver has
// no monitor/injection ioctl path. macgeddon therefore reports the truth
// per interface instead of pretending a capture is running.

module wifi

// ── interfaces ────────────────────────────────────────────────────────

// hardwarePorts(): Iface records from `networksetup`:
//   Hardware Port: Wi-Fi
//   Device: en0
//   Ethernet Address: 68:5e:dd:81:79:18
func hardwarePorts() {
    let text = exec("networksetup -listallhardwareports 2>/dev/null")
    let out = ""
    let port = ""
    let dev = ""
    for l in textLines(text) {
        if startsWith(l, "Hardware Port:") {
            port = trimWS(substring(l, 14, len(l)))
            dev = ""
        }
        if startsWith(l, "Device:") {
            dev = trimWS(substring(l, 7, len(l)))
        }
        if startsWith(l, "Ethernet Address:") {
            let mac = trimWS(substring(l, 17, len(l)))
            if dev != "" {
                out = lstAdd(out, rec(cleanField(dev) + "," + cleanField(port) + "," + cleanField(mac)))
            }
            port = ""
            dev = ""
        }
    }
    emit out
}

func ifaceName(r) { emit recField(r, 0) }
func ifacePort(r) { emit recField(r, 1) }
func ifaceMac(r)  { emit recField(r, 2) }

func ifaceRec(dev) {
    for r in hardwarePorts() {
        if ifaceName(r) == dev { emit r }
    }
    emit rec(cleanField(dev) + ",unknown,")
}

// wifiIface(): device name of the Wi-Fi port, "" when there is none.
func wifiIface() {
    for r in hardwarePorts() {
        if ifacePort(r) == "Wi-Fi" { emit ifaceName(r) }
    }
    emit ""
}

func allIfaces() { emit chomp(exec("ifconfig -l 2>/dev/null")) }

func ifaceActive(dev) {
    let s = chomp(exec("ifconfig " + dev + " 2>/dev/null | grep -c 'status: active'"))
    if s == "0" { emit "0" }
    emit "1"
}

func ifaceIP(dev) { emit chomp(exec("ipconfig getifaddr " + dev + " 2>/dev/null")) }

// ── current network ───────────────────────────────────────────────────

func currentNetwork(dev) {
    let s = chomp(exec("networksetup -getairportnetwork " + dev + " 2>/dev/null"))
    if startsWith(s, "Current Wi-Fi Network:") {
        emit trimWS(substring(s, 24, len(s)))
    }
    emit ""
}

// profiler(): raw `system_profiler SPAirPortDataType` — the only
// unprivileged, documented source of SSID/channel/RSSI/security on macOS.
func profiler(dev) {
    emit exec("system_profiler SPAirPortDataType 2>/dev/null")
}

func currentAP(dev) {
    let aps = parseProfiler(profiler(dev))
    if lstCount(aps) == 0 { emit "" }
    emit lstGet(aps, 0)
}

// ── monitor mode verdict ──────────────────────────────────────────────

// monitorVerdict(): "state:reason".
func monitorVerdict() {
    let dev = wifiIface()
    if dev == "" { emit "no:no Wi-Fi interface on this Mac" }
    if isAppleSilicon() == "1" {
        emit "no:Apple Silicon radio exposes no monitor mode (" + dev + ")"
    }
    if isRoot() == "0" { emit "partial:needs sudo to probe monitor support on " + dev }
    emit "no:macOS exposes no monitor mode to userland (" + dev + ")"
}

func wifiRadioCap() {
    let dev = wifiIface()
    if dev == "" { emit capRec("Wi-Fi radio", "no", "no Wi-Fi hardware port") }
    let v = monitorVerdict()
    let state = "no"
    if startsWith(v, "partial") { state = "partial" }
    if startsWith(v, "yes") { state = "yes" }
    let why = substring(v, indexOf(v, ":") + 1, len(v))
    emit capRec("Wi-Fi " + dev + " (" + ifacePort(ifaceRec(dev)) + ")", state, why)
}

// ── status pages ──────────────────────────────────────────────────────

// printInterfaces(): prints the port table, returns the Wi-Fi device.
func printInterfaces() {
    banner("interfaces", 78)
    print("")
    for r in hardwarePorts() {
        let mark = colorGray("[ -- ]")
        if ifacePort(r) == "Wi-Fi" { mark = colorCyan("[wifi]") }
        print("  " + mark + " " + padR(ifaceName(r), 9) + padR(ifacePort(r), 24) + colorGray(ifaceMac(r)))
    }
    print("")
    let dev = wifiIface()
    if dev == "" {
        warn("no Wi-Fi interface — this Mac has no wireless hardware")
        print("")
        emit ""
    }
    let ap = currentAP(dev)
    if ap == "" {
        info(dev + " is not associated with a network")
    } else {
        print("  " + colorBold("current network"))
        print("")
        print("  " + apHeader())
        print("  " + apLine(apFromRec(ap)))
        print("")
        print("  " + colorGray(apNote(apFromRec(ap))))
    }
    print("")
    emit dev
}

func printRadioVerdict() {
    let dev = wifiIface()
    banner("radio capabilities", 78)
    print("")
    if dev == "" {
        bad("no Wi-Fi interface found")
        print("")
        emit "0"
    }
    let v = monitorVerdict()
    let why = substring(v, indexOf(v, ":") + 1, len(v))
    print("  " + colorBold("interface ") + dev + "   " + colorGray(chip()))
    print("")
    capRender(capRec("monitor mode", "no", why))
    capRender(capRec("frame injection", "no", "no userland 802.11 transmit path"))
    capRender(capRec("associated readout", "yes", "system_profiler SPAirPortDataType"))
    capRender(capRec("neighbour scan", "partial", "cached list from system_profiler; no scan command"))
    print("")
    print("  " + colorYellow("what still works on this host:"))
    print("    - associated-network recon: channel, band, RSSI, security")
    print("    - offline handshake/PMKID cracking (aircrack-ng / hashcat)")
    print("    - parsing scan and capture files produced on a Linux box")
    print("")
    print(colorDim("  see `macgeddon capture --explain` for the full story."))
    print("")
    emit "0"
}

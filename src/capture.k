// src/capture.k — capture gating and orchestration.
//
// This is the part of Airgeddon that cannot be ported to Apple Silicon
// as-is, so it is built the other way round: a preflight that states what
// the radio can do, and only then an attempt. Nothing here pretends to
// capture 802.11 management frames on a radio that cannot deliver them.

module capture

// ── preflight ─────────────────────────────────────────────────────────

func preflight(dev) {
    banner("capture preflight", 78)
    print("")
    if dev == "" {
        bad("no Wi-Fi interface — nothing to capture")
        print("")
        emit "0"
    }
    let verdict = monitorVerdict()
    let why = substring(verdict, indexOf(verdict, ":") + 1, len(verdict))
    print("  " + colorBold("interface ") + dev + "   " + colorGray(chip()))
    print("")
    capRender(capRec("monitor mode", "no", why))
    capRender(capRec("802.11 injection", "no", "no userland TX path"))
    capRender(capRec("EAPOL deauth/capture", "no", "requires monitor mode"))
    capRender(capRec("BPF packet capture", "yes", "tcpdump on the managed interface (no 802.11 headers)"))
    if isRoot() == "1" {
        capRender(capRec("root", "yes", "present"))
    } else {
        capRender(capRec("root", "no", "tcpdump needs sudo; macgeddon will print the command"))
    }
    print("")
    print("  " + colorYellow("verdict: "))
    if isAppleSilicon() == "1" {
        print("    Apple Silicon Wi-Fi cannot enter monitor mode. Handshake, PMKID,")
        print("    deauth and evil-twin capture are not possible on this radio.")
        print("    Use a Linux host with an injection-capable adapter for capture,")
        print("    then bring the .pcap/.pcapng back here for offline cracking.")
    } else {
        print("    this Mac's radio still exposes no monitor mode via macOS.")
    }
    print("")
    emit "0"
}

// ── the two things macOS can actually do ──────────────────────────────

// managedCommand: BPF capture on the managed interface. Useful for
// traffic analysis, never for WPA handshakes (no 802.11 headers).
func managedCommand(dev, out, secs) {
    emit "sudo tcpdump -i " + dev + " -w " + qq(out) + " -G " + secs + " -W 1"
}

func managedCapture(dev, out, secs) {
    banner("managed-interface capture", 78)
    print("")
    info("capturing " + secs + "s of IP traffic on " + dev + " -> " + out)
    print(colorDim("  this is a BPF capture: no 802.11 headers, no EAPOL handshake."))
    print("")
    if isRoot() == "0" {
        warn("not root — run this yourself, then re-run macgeddon on the file:")
        print("")
        print("    " + colorBold(managedCommand(dev, out, secs)))
        print("")
        emit "0"
    }
    let rc = chomp(exec("tcpdump -i " + dev + " -w " + qq(out) + " -G " + secs + " -W 1 2>&1; echo RC=$?"))
    print("")
    if isFile(out) == "1" {
        okRow("wrote " + out + " (" + fileSize(out) + " bytes)")
        emit out
    }
    bad("capture failed: " + rc)
    emit ""
}

// monitorAttempt: one honest try, with the reason recorded when it fails.
func monitorAttempt(dev, out, count) {
    banner("monitor-mode attempt", 78)
    print("")
    if isRoot() == "0" {
        warn("monitor mode needs root; run this and read the result:")
        print("")
        print("    " + colorBold("sudo tcpdump -I -i " + dev + " -y IEEE802_11 -c " + count + " -w " + qq(out)))
        print("")
        print(colorDim("  on Apple Silicon this fails: the driver has no monitor mode."))
        print("")
        emit ""
    }
    let log = chomp(exec("tcpdump -I -i " + dev + " -y IEEE802_11 -c " + count + " -w " + qq(out) + " 2>&1; echo RC=$?"))
    if indexOf(log, "RC=0") >= 0 && isFile(out) == "1" {
        okRow("monitor capture succeeded -> " + out)
        emit out
    }
    bad("monitor mode unavailable")
    print(colorDim("  " + log))
    print("")
    emit ""
}

// explain: the same story in one screen, for the menu.
func explain() {
    banner("why capture is gated", 78)
    print("")
    print("  airgeddon's core loop is: monitor mode -> airodump-ng -> deauth ->")
    print("  capture EAPOL. Every step after the first needs 802.11 frames that")
    print("  macOS does not hand to userland.")
    print("")
    print("  concrete blockers on this host:")
    print("    " + colorGray("- Apple Silicon Wi-Fi driver: no monitor-mode ioctl"))
    print("    " + colorGray("- no frame injection: deauth can never be transmitted"))
    print("    " + colorGray("- `airport` removed in macOS 14.4 (no scan table either)"))
    print("    " + colorGray("- `airmon-ng`/`aireplay-ng` are Linux tools: no `iw`/`iwconfig` here"))
    print("    " + colorGray("- wdutil has no scan command; `info` needs root"))
    print("")
    print("  what macgeddon does instead:")
    print("    " + colorGreen("1.") + " recon + target metadata from system_profiler")
    print("    " + colorGreen("2.") + " offline cracking of handshakes captured elsewhere")
    print("    " + colorGreen("3.") + " conversion and hashcat orchestration on this Mac")
    print("")
}

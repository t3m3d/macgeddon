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
    print("  " + colorBold("interface ") + qq(dev) + "   " + colorGray(chip()))
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
    print("    This build supports managed-interface packet capture only.")
    print("    Monitor capture and frame injection are not implemented.")
    print("    Privileges alone do not add a supported monitor backend.")
    print("")
    emit "0"
}

// ── the two things macOS can actually do ──────────────────────────────

// managedCommand: BPF capture on the managed interface. Useful for
// traffic analysis, never for WPA handshakes (no 802.11 headers).
func managedCommand(dev, out, secs) {
    emit "sudo macgeddon capture --iface " + qq(dev) + " --out " + qq(out) + " --secs " + qq(secs)
}

func managedCapture(dev, out, secs) {
    banner("managed-interface capture", 78)
    print("")
    info("capturing " + secs + "s of IP traffic on " + qq(dev) + " -> " + out)
    print(colorDim("  this is a BPF capture: no 802.11 headers, no EAPOL handshake."))
    print("")
    if isRoot() == "0" {
        warn("not root — run this yourself, then re-run macgeddon on the file:")
        print("")
        print("    " + colorBold(managedCommand(dev, out, secs)))
        print("")
        emit ""
    }
    if isFile(out) == "1" {
        bad("output already exists; choose another --out path")
        emit ""
    }
    // -G rotates only when packets arrive; a separate watchdog supplies an
    // actual wall-clock bound even on a completely idle interface.
    let command = "umask 077; tcpdump -U -i " + qq(dev) + " -w " + qq(out)
    command = command + " & capture_pid=$!; (sleep " + qq(secs) + "; kill -INT \"$capture_pid\" 2>/dev/null) & timer_pid=$!; "
    command = command + "trap 'kill -INT \"$capture_pid\" 2>/dev/null; kill \"$timer_pid\" 2>/dev/null' EXIT HUP INT TERM; "
    command = command + "wait \"$capture_pid\"; capture_rc=$?; kill \"$timer_pid\" 2>/dev/null; wait \"$timer_pid\" 2>/dev/null; echo RC=$capture_rc"
    let rc = chomp(exec(command + " 2>&1"))
    if indexOf(rc, "RC=0") >= 0 && isFile(out) == "1" {
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
        print("    " + colorBold("sudo tcpdump -I -i " + qq(dev) + " -y IEEE802_11 -c " + count + " -w " + qq(out)))
        print("")
        print(colorDim("  on Apple Silicon this fails: the driver has no monitor mode."))
        print("")
        emit ""
    }
    let log = chomp(exec("tcpdump -I -i " + qq(dev) + " -y IEEE802_11 -c " + count + " -w " + qq(out) + " 2>&1; echo RC=$?"))
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
    print("  This native macOS build implements bounded managed-interface capture.")
    print("  It does not implement monitor capture, frame injection, forced")
    print("  handshake collection, PMKID capture, WPS, or evil-twin workflows.")
    print("")
    print("  Interface capabilities depend on hardware, drivers, and macOS.")
    print("  An M-series chip name is not a monitor-mode capability probe.")
    print("  sudo does not supply a backend this application has not implemented.")
    print("")
    print("  Use status, scan, saved-scan imports, reports, or offline analysis.")
    print("  This build neither requires nor connects to a Linux host.")
    print("")
}

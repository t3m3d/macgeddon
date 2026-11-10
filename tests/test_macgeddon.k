#!/usr/bin/env kr
// tests/test_macgeddon.k — offline tests for the macgeddon core.
//
// Built as one translation unit with src/*.k (see scripts/build.sh), so
// every module under test is in scope. No root, no radio, no network:
// every parser is exercised against tests/fixtures/*.

module test_macgeddon

func check(name, got, want) {
    if got == want {
        print(colorGreen("  pass  ") + name)
        emit "0"
    }
    print(colorRed("  FAIL  ") + name + "   got=[" + got + "] want=[" + want + "]")
    emit "1"
}

func checkHas(name, hay, needle) {
    if indexOf(hay, needle) >= 0 {
        print(colorGreen("  pass  ") + name)
        emit "0"
    }
    print(colorRed("  FAIL  ") + name + "   " + jStr(hay) + " lacks " + jStr(needle))
    emit "1"
}

func ap(ssid, bssid, ch, rssi, sec) {
    emit apRec(AP {
        ssid: ssid,
        bssid: bssid,
        channel: ch,
        band: bandOf(ch),
        rssi: rssi,
        security: sec,
        phy: ""
    })
}

just run {
    let fails = 0

    print(colorBold("util — lists, records, splitting"))
    fails = fails + toInt(check("splitAny count", "" + lstCount(splitAny("a b c", " ")), "3"))
    fails = fails + toInt(check("splitAny order", lstGet(splitAny("a b c", " "), 1), "b"))
    fails = fails + toInt(check("splitAny missing delim", splitAny("abc", ","), "abc"))
    fails = fails + toInt(check("recField 1", recField(rec("x,y,z"), 1), "y"))
    fails = fails + toInt(check("recCount", "" + recCount(rec("x,y,z")), "3"))
    fails = fails + toInt(check("recField oob", recField(rec("x,y"), 5), ""))
    fails = fails + toInt(check("lines strips comma", "" + lstCount(lines("a,b" + fromCharCode(10) + "c")), "2"))
    fails = fails + toInt(check("trimWS", trimWS("  x  "), "x"))
    fails = fails + toInt(check("cleanField", cleanField(" a,b "), "a b"))
    fails = fails + toInt(check("padR width", "" + len(padR("ab", 5)), "5"))
    fails = fails + toInt(check("padL int", padL(1, 3), "  1"))
    fails = fails + toInt(check("padR truncates", padR("abcdef", 3), "abc"))
    fails = fails + toInt(check("jsonEsc quote", jsonEsc("a\"b"), "a\\\"b"))

    print(colorBold("model — bands, security, notes"))
    fails = fails + toInt(check("bandOf 44", bandOf("44"), "5"))
    fails = fails + toInt(check("bandOf 6", bandOf("6"), "2.4"))
    fails = fails + toInt(check("bandOf 1", bandOf("1"), "2.4"))
    fails = fails + toInt(check("bandOf 6GHz", bandOf("233"), "6"))
    fails = fails + toInt(check("bandLabel 5", bandLabel("5"), "5G"))
    fails = fails + toInt(check("bandLabel 2.4", bandLabel("2.4"), "2.4G"))
    fails = fails + toInt(check("bandLabel unknown", bandLabel("?"), "?"))
    fails = fails + toInt(check("bandLabelLong unknown", bandLabelLong("?"), "unknown"))
    fails = fails + toInt(checkHas("apLine keeps full security", apLine(apFromRec(ap("x", "aa:aa:aa:aa:aa:09", "44", "-50", "WPA2/WPA3"))), "WPA2/WPA3"))
    fails = fails + toInt(check("securityOf WPA2", securityOf("WPA2 Personal"), "WPA2"))
    fails = fails + toInt(check("securityOf None", securityOf("None"), "Open"))
    fails = fails + toInt(check("securityOf NONE", securityOf("NONE"), "Open"))
    fails = fails + toInt(check("securityOf WPA3", securityOf("WPA3 Personal"), "WPA3"))
    fails = fails + toInt(check("securityOf mixed", securityOf("WPA2/WPA3 Personal"), "WPA2/WPA3"))
    fails = fails + toInt(check("securityOf WEP", securityOf("WEP"), "WEP"))
    fails = fails + toInt(check("securityRank WPA2", securityRank("WPA2"), "3"))
    fails = fails + toInt(check("securityRank open", securityRank("Open"), "0"))
    fails = fails + toInt(checkHas("apNote wpa2", apNote(AP { ssid: "x", bssid: "y", channel: "1", band: "2.4", rssi: "-1", security: "WPA2", phy: "" }), "handshake"))

    print(colorBold("scan — field normalisation"))
    fails = fails + toInt(check("channelOf", channelOf("44 (5GHz, 80MHz)"), "44"))
    fails = fails + toInt(check("rssiOf", rssiOf("-55 dBm / -92 dBm"), "-55"))
    fails = fails + toInt(check("looksMac yes", looksMac("68:5e:dd:81:79:18"), "1"))
    fails = fails + toInt(check("looksMac no", looksMac("nope"), "0"))
    fails = fails + toInt(check("tokens collapse", "" + lstCount(tokens("a   b")), "2"))

    print(colorBold("scan — system_profiler fixture"))
    let prof = readFile("tests/fixtures/profiler.txt")
    let fromProf = parseProfiler(prof)
    fails = fails + toInt(check("profiler count", "" + lstCount(fromProf), "3"))
    fails = fails + toInt(check("profiler ssid", recField(lstGet(fromProf, 0), 0), "HarborNet-5G"))
    fails = fails + toInt(check("profiler channel", recField(lstGet(fromProf, 0), 2), "44"))
    fails = fails + toInt(check("profiler band", recField(lstGet(fromProf, 0), 3), "5"))
    fails = fails + toInt(check("profiler rssi", recField(lstGet(fromProf, 0), 4), "-55"))
    fails = fails + toInt(check("profiler bssid", recField(lstGet(fromProf, 0), 1), "68:5e:dd:81:79:18"))
    fails = fails + toInt(check("profiler open net", recField(lstGet(fromProf, 2), 5), "Open"))
    let noise = readFile("tests/fixtures/profiler_noise.txt")
    let fromNoise = parseProfiler(noise)
    fails = fails + toInt(check("interface block dropped", "" + lstCount(fromNoise), "1"))
    fails = fails + toInt(check("real ap kept", recField(lstGet(fromNoise, 0), 0), "Neighbour"))
    fails = fails + toInt(check("parseAPs no loose fallback", "" + lstCount(parseAPs(noise)), "1"))

    print(colorBold("scan — legacy / loose fixtures"))
    let fromAirport = parseLoose(readFile("tests/fixtures/airport_s.txt"))
    fails = fails + toInt(check("airport count", "" + lstCount(fromAirport), "3"))
    fails = fails + toInt(check("airport ssid", recField(lstGet(fromAirport, 0), 0), "HarborNet-5G"))
    fails = fails + toInt(check("airport rssi", recField(lstGet(fromAirport, 0), 4), "-55"))
    let fromRowlist = parseLoose(readFile("tests/fixtures/rowlist.txt"))
    fails = fails + toInt(check("rowlist count", "" + lstCount(fromRowlist), "3"))
    fails = fails + toInt(check("rowlist channel", recField(lstGet(fromRowlist, 1), 2), "6"))
    fails = fails + toInt(check("parseAPs dispatch", "" + lstCount(parseAPs(prof)), "3"))

    print(colorBold("scan — ordering, dedupe, persistence"))
    let mixed = lstAdd("", ap("weak", "aa:aa:aa:aa:aa:01", "6", "-85", "WPA2"))
    mixed = lstAdd(mixed, ap("strong", "aa:aa:aa:aa:aa:02", "44", "-45", "WPA2"))
    mixed = lstAdd(mixed, ap("mid", "aa:aa:aa:aa:aa:03", "11", "-70", "Open"))
    let sorted = sortByRssi(mixed)
    fails = fails + toInt(check("sorted strongest", recField(lstGet(sorted, 0), 4), "-45"))
    fails = fails + toInt(check("sorted weakest", recField(lstGet(sorted, 2), 4), "-85"))
    let dup = lstAdd(mixed, ap("strong-again", "aa:aa:aa:aa:aa:02", "44", "-46", "WPA2"))
    fails = fails + toInt(check("dedupe count", "" + lstCount(dedupe(dup)), "3"))

    ensureDir("/tmp/macgeddon-test")
    saveTargets(sorted, "/tmp/macgeddon-test/targets.txt")
    let reloaded = loadTargets("/tmp/macgeddon-test/targets.txt")
    fails = fails + toInt(check("targets roundtrip", "" + lstCount(reloaded), "3"))
    fails = fails + toInt(check("targets bssid kept", recField(lstGet(reloaded, 0), 1), "aa:aa:aa:aa:aa:02"))
    fails = fails + toInt(check("loadTargets missing", loadTargets("/tmp/macgeddon-test/nope.txt"), ""))

    print(colorBold("report — summaries and JSON"))
    fails = fails + toInt(check("bandSummary", bandSummary(sorted), "2.4GHz:2,5GHz:1"))
    fails = fails + toInt(check("countWhere open", "" + countWhere(sorted, 5, "Open"), "1"))
    fails = fails + toInt(checkHas("targetsJSON ssid", targetsJSON(sorted), "\"ssid\":\"weak\""))
    fails = fails + toInt(checkHas("targetsJSON note", targetsJSON(sorted), "\"note\""))
    fails = fails + toInt(checkHas("capsJSON", capsJSON(wifiCaps()), "\"frame injection\""))
    fails = fails + toInt(checkHas("capsJSON state", capsJSON(wifiCaps()), "\"state\""))

    print(colorBold("remote — airgeddon toolchain on a Linux host"))
    fails = fails + toInt(check("monitor name", parseMonitorName("(monitor mode enabled on wlan0mon)"), "wlan0mon"))
    fails = fails + toInt(check("monitor name missing", parseMonitorName("no monitor here"), ""))
    fails = fails + toInt(checkHas("ssh batch mode", sshBase("u@h", "22"), "BatchMode=yes"))
    fails = fails + toInt(checkHas("probe asks airmon-ng", remoteProbeCmd("u@h", "22"), "airmon-ng=1"))
    fails = fails + toInt(checkHas("dump is bounded", remoteDumpCmd("u@h", "22", "wlan0mon", "aa:bb", "6", "30", "/tmp/x"), "timeout 30 airodump-ng"))
    fails = fails + toInt(checkHas("dump filters bssid", remoteDumpCmd("u@h", "22", "wlan0mon", "aa:bb", "6", "30", "/tmp/x"), "--bssid aa:bb"))
    fails = fails + toInt(checkHas("deauth uses aireplay", remoteDeauthCmd("u@h", "22", "wlan0mon", "aa:bb", "8"), "aireplay-ng --deauth 8"))
    fails = fails + toInt(checkHas("pull uses scp", remotePullCmd("22", "u@h", "/tmp/x-01.cap", "/tmp/y.cap"), "u@h:/tmp/x-01.cap"))
    let csvAps = parseAirodumpCSV(readFile("tests/fixtures/airodump.csv"))
    fails = fails + toInt(check("csv count", "" + lstCount(csvAps), "3"))
    fails = fails + toInt(check("csv ssid comma neutralised", recField(lstGet(csvAps, 1), 0), "Cafe  Guest Free"))
    fails = fails + toInt(check("csv mixed security", recField(lstGet(csvAps, 1), 5), "WPA2/WPA3"))
    fails = fails + toInt(check("csv open mapped", recField(lstGet(csvAps, 2), 5), "Open"))
    fails = fails + toInt(check("csv rssi", recField(lstGet(csvAps, 2), 4), "-84"))
    fails = fails + toInt(check("csv band", recField(lstGet(csvAps, 0), 3), "5"))

    print(colorBold("crack — classification and hints"))
    fails = fails + toInt(check("kind pcap", artifactKind("a.pcap"), "pcap"))
    fails = fails + toInt(check("kind pcapng", artifactKind("a.pcapng"), "pcapng"))
    fails = fails + toInt(check("kind 22000", artifactKind("a.22000"), "22000"))
    fails = fails + toInt(check("kind txt", artifactKind("a.txt"), "wordlist"))
    fails = fails + toInt(check("isCapture", isCapture("a.pcap") + isCapture("a.txt"), "10"))
    fails = fails + toInt(checkHas("maskHint digits", maskHint("iPhone123"), "?d"))
    fails = fails + toInt(checkHas("maskHint generic", maskHint("MyNet12345"), "?a"))
    fails = fails + toInt(checkHas("aircrackCommand", aircrackCommand("/t/a.cap", "/t/w.txt", "aa:bb"), "aircrack-ng"))
    fails = fails + toInt(checkHas("hashcatCommand", hashcatCommand("/t/a.22000", "/t/w.txt", "", "/t/pot"), "-m 22000"))

    print("")
    if fails == 0 {
        print(colorBold(colorGreen("ALL TESTS PASSED")))
    } else {
        print(colorBold(colorRed("TESTS FAILED: " + fails)))
    }
    print("")
    // Exit status is the gate: scripts/build.sh only trusts it, so a failing
    // assertion must fail the build instead of printing and returning 0.
    if fails > 0 { exit(1) }
}

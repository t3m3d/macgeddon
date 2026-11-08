module macgeddon_model

// CoreWLAN CWSecurity values, including the two aggregate query values.
func securityLabel(value) {
    if value < 0 || value > 15 { emit "Unknown" }
    emit getLine("Open\nWEP\nWPA Personal\nWPA/WPA2 Personal\nWPA2 Personal\nPersonal (aggregate)\nDynamic WEP\nWPA Enterprise\nWPA/WPA2 Enterprise\nWPA2 Enterprise\nEnterprise (aggregate)\nWPA3 Personal\nWPA3 Enterprise\nWPA2/WPA3 Transition\nOWE\nOWE Transition", value)
}

func securityFinding(value) {
    if value == 0 { emit "Unencrypted network; traffic has no Wi-Fi link encryption." }
    if value == 1 || value == 6 { emit "WEP is obsolete; replace with WPA2-AES or WPA3." }
    if value == 2 || value == 3 || value == 7 || value == 8 {
        emit "Legacy WPA support advertised; review configuration and disable WPA1."
    }
    if value == 13 { emit "Transition mode permits WPA2 clients; review whether WPA3-only is feasible." }
    if value == 15 { emit "OWE transition mode permits unencrypted clients." }
    emit ""
}

func bandLabel(value) {
    if value == 1 { emit "2.4 GHz" }
    if value == 2 { emit "5 GHz" }
    if value == 3 { emit "6 GHz" }
    emit "Unknown"
}

// Never print control sequences supplied by a nearby access point.
func terminalText(text) {
    let result = ""
    let i = 0
    while i < len(text) {
        let c = text[i]
        let code = charCode(c)
        if code < 32 || code == 127 { result = result + "?" }
        else { result = result + c }
        i += 1
    }
    emit result
}

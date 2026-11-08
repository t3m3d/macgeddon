module macgeddon_wifi

// All radio access is through the public CoreWLAN framework. Native handles
// remain pointers throughout; converting them to text loses their ABI type.
func loadFramework(name) {
    let path = "/System/Library/Frameworks/" + name + ".framework"
    let bundle = msg_1(cls("NSBundle"), "bundleWithPath:", nsString(path))
    emit msg(bundle, "load")
}

func wifiClient() {
    if loadFramework("CoreWLAN") == 0 {
        printErr("macgeddon: CoreWLAN could not be loaded.")
        exit(3)
    }
    emit msg(cls("CWWiFiClient"), "sharedWiFiClient")
}

func dictNew() { emit msg(cls("NSMutableDictionary"), "dictionary") }
func arrayNew() { emit msg(cls("NSMutableArray"), "array") }
func put(dict, key, value) { msg_2(dict, "setObject:forKey:", value, nsString(key)) }
func putText(dict, key, value) { put(dict, key, nsString(value)) }
func putNumber(dict, key, value) { put(dict, key, msg_1(cls("NSNumber"), "numberWithInteger:", value)) }
func putBool(dict, key, value) { put(dict, key, msg_1(cls("NSNumber"), "numberWithBool:", value)) }
func add(array, value) { msg_1(array, "addObject:", value) }
func get(dict, key) { emit msg_1(dict, "objectForKey:", nsString(key)) }

func jsonText(object) {
    let data = msg_3(cls("NSJSONSerialization"), "dataWithJSONObject:options:error:", object, 3, 0)
    if data == 0 {
        printErr("macgeddon: JSON serialization failed.")
        exit(3)
    }
    let text = msg_2(msg(cls("NSString"), "alloc"), "initWithData:encoding:", data, 4)
    msg(text, "autorelease")
    emit nsToStr(text)
}

func putOptionalText(dict, key, object) {
    if object == 0 { put(dict, key, msg(cls("NSNull"), "null")) }
    else { put(dict, key, object) }
}

func selectedInterface(client, name) {
    let interfaces = msg(client, "interfaces")
    let i = 0
    while i < msg(interfaces, "count") {
        let iface = msg_1(interfaces, "objectAtIndex:", i)
        if name == "" || nsToStr(msg(iface, "interfaceName")) == name { emit iface }
        i += 1
    }
    if name == "" { printErr("macgeddon: No Wi-Fi interfaces available. Check hardware and system permissions.") }
    else { printErr("macgeddon: Wi-Fi interface not found: " + terminalText(name)) }
    exit(3)
}

func channelRecord(channel) {
    if channel == 0 { emit msg(cls("NSNull"), "null") }
    let row = dictNew()
    putNumber(row, "number", msg(channel, "channelNumber"))
    putText(row, "band", bandLabel(msg(channel, "channelBand")))
    // CoreWLAN enum: 0=unknown, 1=20, 2=40, 3=80, 4=160 MHz.
    putNumber(row, "width_enum", msg(channel, "channelWidth"))
    emit row
}

func interfaceRecord(iface) {
    let row = dictNew()
    putOptionalText(row, "name", msg(iface, "interfaceName"))
    putBool(row, "power_on", msg(iface, "powerOn"))
    putOptionalText(row, "ssid", msg(iface, "ssid"))
    putOptionalText(row, "bssid", msg(iface, "bssid"))
    putOptionalText(row, "country", msg(iface, "countryCode"))
    put(row, "channel", channelRecord(msg(iface, "wlanChannel")))
    putNumber(row, "rssi_dbm", msg(iface, "rssiValue"))
    putNumber(row, "noise_dbm", msg(iface, "noiseMeasurement"))
    putText(row, "security", securityLabel(msg(iface, "security")))
    emit row
}

func interfaceRecords(client) {
    let result = arrayNew()
    let interfaces = msg(client, "interfaces")
    let i = 0
    while i < msg(interfaces, "count") {
        add(result, interfaceRecord(msg_1(interfaces, "objectAtIndex:", i)))
        i += 1
    }
    emit result
}

func networkRecord(network) {
    let row = dictNew()
    putOptionalText(row, "ssid", msg(network, "ssid"))
    putOptionalText(row, "bssid", msg(network, "bssid"))
    putOptionalText(row, "country", msg(network, "countryCode"))
    put(row, "channel", channelRecord(msg(network, "wlanChannel")))
    putNumber(row, "rssi_dbm", msg(network, "rssiValue"))
    putNumber(row, "noise_dbm", msg(network, "noiseMeasurement"))
    let security = arrayNew()
    let findings = arrayNew()
    let code = 0
    while code <= 15 {
        // 5 and 10 are aggregate query types, not individual security modes.
        if code != 5 && code != 10 {
            if msg_1(network, "supportsSecurity:", code) != 0 {
                add(security, nsString(securityLabel(code)))
                let finding = securityFinding(code)
                if finding != "" && msg_1(findings, "containsObject:", nsString(finding)) == 0 {
                    add(findings, nsString(finding))
                }
            }
        }
        code += 1
    }
    put(row, "security", security)
    put(row, "findings", findings)
    emit row
}

func scanRecords(iface) {
    if msg(iface, "powerOn") == 0 {
        printErr("macgeddon: Wi-Fi is off. Enable Wi-Fi in System Settings.")
        exit(3)
    }
    // NSPointerArray provides a real NSError** without relying on unsafe
    // integer/pointer conversions in the Krypton buffer API.
    let errors = msg(cls("NSPointerArray"), "weakObjectsPointerArray")
    msg_1(errors, "addPointer:", 0)
    // A plain 8-byte buffer is the documented foreign-call writable pointer.
    let errorStorage = bufNew(8)
    bufSetQwordAt(errorStorage, 0, 0)
    let networks = msg_2(iface, "scanForNetworksWithName:error:", 0, errorStorage)
    if networks == 0 {
        printErr("macgeddon: Scan failed. Enable Location Services, authorize the launching app, and check Wi-Fi.")
        exit(3)
    }
    let result = arrayNew()
    let items = msg(networks, "allObjects")
    let sorter = msg_2(cls("NSSortDescriptor"), "sortDescriptorWithKey:ascending:", nsString("rssiValue"), 0)
    let sorters = arrayNew()
    add(sorters, sorter)
    items = msg_1(items, "sortedArrayUsingDescriptors:", sorters)
    let i = 0
    while i < msg(items, "count") {
        add(result, networkRecord(msg_1(items, "objectAtIndex:", i)))
        i += 1
    }
    emit result
}

func channelCounts(networks) {
    let counts = dictNew()
    let i = 0
    while i < msg(networks, "count") {
        let row = msg_1(networks, "objectAtIndex:", i)
        let channel = get(row, "channel")
        if channel != msg(cls("NSNull"), "null") {
            let key = nsToStr(get(channel, "band")) + " / " + nsToStr(get(channel, "number"))
            let old = get(counts, key)
            putNumber(counts, key, msg(old, "integerValue") + 1)
        }
        i += 1
    }
    emit counts
}

func supportedChannels(iface) {
    let result = arrayNew()
    let channels = msg(msg(iface, "supportedWLANChannels"), "allObjects")
    let i = 0
    while i < msg(channels, "count") {
        add(result, channelRecord(msg_1(channels, "objectAtIndex:", i)))
        i += 1
    }
    emit result
}

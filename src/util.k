// src/util.k — small pure-Krypton helpers shared by every macgeddon module.
//
// Krypton rules this file is written around:
//   * text is byte-indexed; "list" is a comma-separated string
//   * split(list, i) indexes that list; there is no delimiter-split builtin,
//     so splitAny() is hand-rolled
//   * "a" + "b" is arithmetic when BOTH sides are all digits, so record
//     fields are always joined with a separator, never bare concat
//   * len() measures text; count()/length() count comma-list items
//   * fields inside one record are joined with US (0x1f) so a record is a
//     single list item even when it holds SSIDs with punctuation

module util

// ── field records ─────────────────────────────────────────────────────
// A record is one list item whose fields are separated by US (0x1f).
// Field values must never contain US or a comma (callers sanitize).

func US() { emit fromCharCode(31) }

// char access: s[i] returns the byte at an integer index. A text index such
// as s["3"] yields "" rather than raising, so callers pass integer counters
// only. chAt is one character, codeAt its code.
func chAt(s, i) {
    if i < 0 { emit "" }
    if i >= len(s) { emit "" }
    emit s[i]
}

func codeAt(s, i) {
    if i < 0 { emit -1 }
    if i >= len(s) { emit -1 }
    emit toInt(charCode(s[i]))
}

// rec(parts): join a comma-list of field values into one US-joined record.
func rec(parts) {
    let out = ""
    let i = 0
    let n = count(parts)
    while i < n {
        let part = split(parts, i)
        if i == 0 { out = part } else { out = out + US() + part }
        i += 1
    }
    emit out
}

// recField(r, i): field i of a record, "" when out of range.
func recField(r, i) {
    let cur = 0
    let start = 0
    let n = len(r)
    let j = 0
    while j <= n {
        let atEnd = j == n
        let isSep = 0
        if atEnd == 0 {
            if codeAt(r, j) == 31 { isSep = 1 }
        }
        if isSep == 1 || atEnd == 1 {
            if cur == i { emit substring(r, start, j) }
            cur += 1
            start = j + 1
        }
        j += 1
    }
    emit ""
}

// recCount(r): number of fields in a record.
func recCount(r) {
    let n = 1
    let i = 0
    while i < len(r) {
        if codeAt(r, i) == 31 { n += 1 }
        i += 1
    }
    emit n
}

// ── comma lists ───────────────────────────────────────────────────────

// lstAdd(l, item): append one item. Item must not contain a comma.
func lstAdd(l, item) {
    if l == "" { emit item }
    emit l + "," + item
}

func lstCount(l) {
    if l == "" { emit 0 }
    emit count(l)
}

func lstGet(l, i) { emit split(l, i) }

// ── string splitting ──────────────────────────────────────────────────

// splitAny(s, delim): every piece of s between occurrences of delim.
// Returns "" for an empty input. A blank delimiter is treated as a no-op.
func splitAny(s, delim) {
    if delim == "" { emit s }
    if s == "" { emit "" }
    let out = ""
    let rest = s
    let dl = len(delim)
    let guard = 0
    while guard < 4096 {
        guard += 1
        let i = indexOf(rest, delim)
        if i < 0 {
            emit lstAdd(out, rest)
        }
        out = lstAdd(out, substring(rest, 0, i))
        rest = substring(rest, i + dl, len(rest))
    }
    emit out
}

// textLines(text): non-empty, whitespace-trimmed lines of a blob of text.
//
// Scanned character by character on purpose: Krypton's `replace` does not
// reliably rewrite control characters, and a comma-list cannot hold an
// item with a comma in it, so LF/CR split the lines and commas become
// spaces (no value macgeddon needs from these files contains a comma).
func textLines(text) {
    let out = ""
    let cur = ""
    let i = 0
    let n = len(text)
    while i <= n {
        let atEnd = i == n
        let isSep = 0
        let c = -1
        if atEnd == 0 { c = codeAt(text, i) }
        if c == 10 || c == 13 { isSep = 1 }
        if isSep == 1 || atEnd == 1 {
            let t = trimWS(cur)
            if t != "" { out = lstAdd(out, t) }
            cur = ""
        } else {
            if c == 44 { cur = cur + " " } else { cur = cur + chAt(text, i) }
        }
        i += 1
    }
    emit out
}

// trimWS(s): strip spaces, tabs and stray CR/LF from both ends.
func trimWS(s) {
    let lo = 0
    let hi = len(s)
    while lo < hi {
        let c = codeAt(s, lo)
        if c == 32 || c == 9 || c == 10 || c == 13 { lo += 1 } else { break }
    }
    while hi > lo {
        let c = codeAt(s, hi - 1)
        if c == 32 || c == 9 || c == 10 || c == 13 { hi -= 1 } else { break }
    }
    emit substring(s, lo, hi)
}

// cleanField(s): make a value safe to store inside a US-joined record.
func cleanField(s) {
    let t = trimWS(s)
    t = replace(t, US(), " ")
    t = replace(t, ",", " ")
    emit t
}

// ── padding / layout ──────────────────────────────────────────────────

func repeatCh(ch, n) {
    let out = ""
    let i = 0
    while i < n {
        out = out + ch
        i += 1
    }
    emit out
}

// padR(s, n): left-aligned in n columns, truncated if longer.
// Values are coerced to text first: len() measures text, and callers pass
// row counters here as well as names.
func padR(s, n) {
    let t = "" + s
    if len(t) > n { t = substring(t, 0, n) }
    emit t + repeatCh(" ", n - len(t))
}

// padL(s, n): right-aligned in n columns.
func padL(s, n) {
    let t = "" + s
    if len(t) > n { t = substring(t, len(t) - n, len(t)) }
    emit repeatCh(" ", n - len(t)) + t
}

func dash(n) { emit repeatCh("-", n) }

func banner(title, width) {
    print("")
    print(colorBold(colorCyan("+" + dash(width - 2) + "+")))
    print(colorBold(colorCyan("| " + padR(title, width - 4) + " |")))
    print(colorBold(colorCyan("+" + dash(width - 2) + "+")))
}

// ── colour ────────────────────────────────────────────────────────────

func esc() { emit fromCharCode(27) }

func color(code, s) {
    emit esc() + "[" + code + "m" + s + esc() + "[0m"
}

func colorBold(s)   { emit color("1", s) }
func colorDim(s)    { emit color("2", s) }
func colorRed(s)    { emit color("31", s) }
func colorGreen(s)  { emit color("32", s) }
func colorYellow(s) { emit color("33", s) }
func colorBlue(s)   { emit color("34", s) }
func colorCyan(s)   { emit color("36", s) }
func colorGray(s)   { emit color("90", s) }

// ok/bad/warn/info: one-line status rows used all over the UI.
func okRow(msg)   { print("  " + colorGreen("[ ok ]") + " " + msg) }
func bad(msg)  { print("  " + colorRed("[fail]") + " " + msg) }
func warn(msg) { print("  " + colorYellow("[warn]") + " " + msg) }
func info(msg) { print("  " + colorCyan("[info]") + " " + msg) }
func skip(msg) { print("  " + colorGray("[ -- ]") + " " + colorGray(msg)) }

// ── shell / fs ────────────────────────────────────────────────────────

// chomp(s): strip surrounding whitespace from command output.
func chomp(s) { emit trimWS(s) }

func shOut(cmd) { emit chomp(exec(cmd)) }
func shRaw(cmd) { emit exec(cmd) }

// shOk(cmd): "1" when the command exits 0.
func shOk(cmd) { emit chomp(exec("( " + cmd + " ) >/dev/null 2>&1 && echo 1 || echo 0")) }

func which(name) { emit chomp(exec("command -v " + name + " 2>/dev/null")) }
func hasTool(name) {
    if which(name) == "" { emit "0" }
    emit "1"
}

func pathExists(p)  { emit shOk("test -e " + qq(p)) }
func isDir(p)       { emit shOk("test -d " + qq(p)) }
func isFile(p)      { emit shOk("test -f " + qq(p)) }
func fileSize(p)    { emit chomp(exec("stat -f%z " + qq(p) + " 2>/dev/null")) }
func ensureDir(p)   { exec("mkdir -p " + qq(p)) emit "1" }
func listDir(p)     { emit textLines(exec("ls -1 " + qq(p) + " 2>/dev/null")) }
func readAll(p)     { emit readFile(p) }
func writeAll(p, t) { writeFile(p, t) emit "1" }
func rmFile(p)      { exec("rm -f " + qq(p)) emit "1" }

// qq(s): double-quote a shell argument and neutralise embedded quotes.
func qq(s) {
    emit "\"" + replace(s, "\"", "\\\"") + "\""
}

func nowEpoch() { emit chomp(exec("date +%s")) }
func nowISO()   { emit chomp(exec("date -u +%Y-%m-%dT%H:%M:%SZ")) }
func stamp()    { emit chomp(exec("date +%Y%m%d-%H%M%S")) }
func hostName() { emit chomp(exec("hostname 2>/dev/null")) }

// ── JSON ──────────────────────────────────────────────────────────────

func jsonEsc(s) {
    let t = replace(s, "\\", "\\\\")
    t = replace(t, "\"", "\\\"")
    t = replace(t, fromCharCode(10), "\\n")
    t = replace(t, fromCharCode(13), "")
    t = replace(t, fromCharCode(9), "\\t")
    emit t
}

func jStr(s)  { emit "\"" + jsonEsc(s) + "\"" }
func jPair(k, v)  { emit "    " + jStr(k) + ": " + jStr(v) }
func jPairN(k, v) { emit "    " + jStr(k) + ": " + v }

// arrJoin(items): turn a comma-list of JSON fragments into an array literal.
func arrJoin(items) {
    let out = "["
    let i = 0
    let n = lstCount(items)
    while i < n {
        if i > 0 { out = out + "," }
        out = out + lstGet(items, i)
        i += 1
    }
    emit out + "]"
}

// objJoin(pairs): turn a comma-list of "key:value" fragments into an object.
// Fragments are already-quoted JSON members; they may not contain commas,
// so callers build them with jPair() and add via lstAdd.
func objJoin(pairs) {
    let out = "{"
    let i = 0
    let n = lstCount(pairs)
    while i < n {
        if i > 0 { out = out + "," }
        out = out + lstGet(pairs, i)
        i += 1
    }
    emit out + "}"
}

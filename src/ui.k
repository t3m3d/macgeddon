#!/usr/bin/env kr
// src/ui.k — macgeddon in Objective-K (Krypton -> AppKit via Choc).
//
// No Obj-C, no Swift: the window, buttons and text view are driven by
// Krypton funcs registered as native UI callbacks. The GUI is a front end
// to the same compiled CLI, so behaviour can never drift from the terminal
// tool: it shells out to bin/macgeddon and shows the output.
//
// Build: scripts/build.sh builds this to bin/macgeddon-gui.
// Note: a GUI needs a real window server session; this is not covered by
// tests/test_macgeddon.k (compile-time proof only).

import "k:cocoa"

// The GUI is compiled on its own (not as part of the CLI translation
// unit), so it cannot use the util.k helpers: everything it needs is
// defined here. A cross-file call without an import is an unknown-function
// error, so these helpers are required, not optional.
func trimEnd(s) {
    let hi = len(s)
    while hi > 0 {
        let c = toInt(charCode(substring(s, hi - 1, hi)))
        if c == 32 || c == 9 || c == 10 || c == 13 { hi -= 1 } else { break }
    }
    emit substring(s, 0, hi)
}

// getenvFallback is defined before its caller: Krypton resolves calls in
// one pass, so a forward reference inside the same file fails codegen.
func getenvFallback(name, dflt) {
    let v = exec("printenv " + name)
    let t = trimEnd(v)
    if t == "" { emit dflt }
    emit t
}

// cliPath: the sibling binary produced by scripts/build.sh.
func cliPath() {
    emit getenvFallback("MACGEDDON_BIN", "bin/macgeddon")
}

// runCmd: run a subcommand and return its text for the output pane.
func runCmd(args) {
    let out = exec(cliPath() + " " + args + " 2>&1")
    if out == "" { emit "(no output)" }
    emit out
}

// ── actions (native callbacks: self, _cmd, sender) ────────────────────

func onStatus(self, cmd, sender) {
    let pane = cocoaGetAssoc(sender)
    cocoaSetText(pane, runCmd("status"))
}

func onCaps(self, cmd, sender) {
    let pane = cocoaGetAssoc(sender)
    cocoaSetText(pane, runCmd("caps"))
}

func onScan(self, cmd, sender) {
    let pane = cocoaGetAssoc(sender)
    cocoaSetText(pane, runCmd("scan"))
}

func onDoctor(self, cmd, sender) {
    let pane = cocoaGetAssoc(sender)
    cocoaSetText(pane, runCmd("doctor"))
}

func onExplain(self, cmd, sender) {
    let pane = cocoaGetAssoc(sender)
    cocoaSetText(pane, runCmd("capture --explain"))
}

// ── window ────────────────────────────────────────────────────────────

just run {
    // Values are computed into locals first: objk lowers a call argument
    // best when it is a variable, not a nested call.
    let ver = runCmd("version")
    let ifc = runCmd("ifaces")
    let app = cocoaInit()
    let win = cocoaWindow(app, "macgeddon " + ver, 820, 520)

    let head = cocoaLabel(win, "recon and offline WPA work for Apple Silicon - capture is gated", 24, 470, 772, 22)
    let dev = cocoaLabel(win, ifc, 24, 300, 372, 150)
    let pane = cocoaLabel(win, "press a button", 412, 60, 384, 390)

    let b1 = cocoaButton(win, "status",  24, 20, 110, 30)
    let b2 = cocoaButton(win, "caps",   142, 20, 110, 30)
    let b3 = cocoaButton(win, "scan",   260, 20, 110, 30)
    let b4 = cocoaButton(win, "doctor", 378, 20, 110, 30)
    let b5 = cocoaButton(win, "why capture is gated", 496, 20, 200, 30)

    cocoaSetAssoc(b1, pane)
    cocoaSetAssoc(b2, pane)
    cocoaSetAssoc(b3, pane)
    cocoaSetAssoc(b4, pane)
    cocoaSetAssoc(b5, pane)

    cocoaOnClick(b1, funcptr(onStatus))
    cocoaOnClick(b2, funcptr(onCaps))
    cocoaOnClick(b3, funcptr(onScan))
    cocoaOnClick(b4, funcptr(onDoctor))
    cocoaOnClick(b5, funcptr(onExplain))

    cocoaShow(win, app)
    cocoaRun(app)
}

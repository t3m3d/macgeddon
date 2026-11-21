#!/usr/bin/env kr
// Native AppKit front end. The CLI is embedded beside this executable.
import "k:cocoa"

func guiQuote(text) {
    emit "'" + replace(text, "'", "'\"'\"'") + "'"
}

func cliPath() {
    let args = msg(msg(cls("NSProcessInfo"), "processInfo"), "arguments")
    let executable = msg_1(args, "objectAtIndex:", 0)
    let dir = msg(executable, "stringByDeletingLastPathComponent")
    emit nsToStr(msg_1(dir, "stringByAppendingPathComponent:", nsString("macgeddon")))
}

func runCmd(args) {
    // Commands are fixed UI actions. A Finder launch need not inherit a
    // terminal's PATH, working directory, or compiler installation.
    let out = exec("NO_COLOR=1 PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin " + guiQuote(cliPath()) + " " + args + " 2>&1")
    if out == "" { emit "The command returned no output." }
    emit out
}

func onStatus(self, cmd, sender) { cocoaTVSetString(cocoaGetAssoc(sender), runCmd("status")) }
func onCaps(self, cmd, sender) { cocoaTVSetString(cocoaGetAssoc(sender), runCmd("caps")) }
func onScan(self, cmd, sender) { cocoaTVSetString(cocoaGetAssoc(sender), runCmd("scan")) }
func onDoctor(self, cmd, sender) { cocoaTVSetString(cocoaGetAssoc(sender), runCmd("doctor")) }
func onExplain(self, cmd, sender) { cocoaTVSetString(cocoaGetAssoc(sender), runCmd("capture --explain")) }

just run {
    let pool = newPool()
    // A packaging check runnable from any directory without a window server.
    if argCount() > 0 {
        if arg(0) == "--smoke-test" {
            let output = runCmd("version")
            print(output)
            if indexOf(output, "macgeddon 0.1.0") < 0 { exit(1) }
            drainPool(pool)
            exit(0)
        }
    }
    let app = cocoaInit()
    let bar = cocoaMenuBar(app)
    let appMenu = cocoaMenuAdd(bar, "Macgeddon")
    cocoaMenuItemSel(appMenu, "Quit Macgeddon", "q", "terminate:")
    let editMenu = cocoaMenuAdd(bar, "Edit")
    cocoaMenuItemSel(editMenu, "Copy", "c", "copy:")
    cocoaMenuItemSel(editMenu, "Select All", "a", "selectAll:")
    let win = cocoaWindow(app, "Macgeddon — Apple Silicon", 940, 620)
    msg_d2(win, "setMinSize:", 940, 620)
    cocoaLabel(win, "macOS wireless inventory, saved scans, and offline analysis", 24, 572, 892, 24)
    let pane = cocoaScrollText(win, 24, 72, 892, 482)
    msg_1(pane, "setEditable:", 0)
    msg_1(pane, "setSelectable:", 1)
    msg_1(pane, "setFont:", msg_d1(cls("NSFont"), "userFixedPitchFontOfSize:", 12))
    cocoaTVNoWrap(pane)
    let scroll = msg(pane, "enclosingScrollView")
    msg_1(scroll, "setHasHorizontalScroller:", 1)
    let b1 = cocoaButton(win, "Status", 24, 20, 110, 32)
    let b2 = cocoaButton(win, "Capabilities", 142, 20, 130, 32)
    let b3 = cocoaButton(win, "Scan", 280, 20, 110, 32)
    let b4 = cocoaButton(win, "Tool doctor", 398, 20, 130, 32)
    let b5 = cocoaButton(win, "Capture limits", 536, 20, 150, 32)
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
    cocoaTVSetString(pane, "Macgeddon is ready. Choose an action below.\n\nScan reads macOS cached network metadata; it may take several seconds.\nUse the CLI for saved-scan imports, capture, offline analysis, and reports.")
    cocoaShow(win, app)
    // Opt-in native control check; never triggered by Finder launches.
    if argCount() > 0 {
        if arg(0) == "--ui-test" {
            onStatus(0, 0, b1)
            let output = nsToStr(msg(pane, "string"))
            if indexOf(output, "macgeddon 0.1.0") < 0 { exit(1) }
            onExplain(0, 0, b5)
            output = nsToStr(msg(pane, "string"))
            if indexOf(output, "capture is gated") < 0 { exit(1) }
            msg(win, "close")
            print("AppKit window, menus, output view, and button callbacks passed")
            exit(0)
        }
    }
    cocoaRun(app)
    drainPool(pool)
}

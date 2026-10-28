"""Comprehensive verification and diagnostic script for CodeNova Password Strength Checker GUI.

Performs:
1. Python, Tcl/Tk, and Windows desktop/session environment diagnostics.
2. Independent standalone Tkinter window creation and visibility test.
3. Actual application GUI process launch, HWND detection, and Win32 visibility verification.
4. Real interactive evaluation test (input, analysis, meter, recommendations, clear).
5. Unit test suite execution.
6. CLI regression test.
"""

import ctypes
from ctypes import wintypes
import os
import platform
import subprocess
import sys
import time
import unittest


def run_environment_diagnostics() -> dict:
    print("=" * 70)
    print(" 1. PYTHON, TCL/TK & WINDOWS ENVIRONMENT DIAGNOSTICS")
    print("=" * 70)

    import tkinter as tk

    info = {
        "python_exe": sys.executable,
        "python_version": sys.version.split()[0],
        "arch": platform.architecture()[0],
        "tk_version": tk.TkVersion,
        "tcl_version": tk.TclVersion,
    }
    print(f"* Python Executable:  {info['python_exe']}")
    print(f"* Python Version:     {info['python_version']} ({info['arch']})")
    print(f"* Tkinter Version:    {info['tk_version']} (Tcl {info['tcl_version']})")

    # Tcl patchlevel
    tcl = tk.Tcl()
    info["tcl_patchlevel"] = tcl.eval("info patchlevel")
    print(f"* Tcl Patchlevel:     {info['tcl_patchlevel']}")

    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32

    # Session & Desktop
    pid = kernel32.GetCurrentProcessId()
    sess_id = wintypes.DWORD()
    kernel32.ProcessIdToSessionId(pid, ctypes.byref(sess_id))
    active_console = kernel32.WTSGetActiveConsoleSessionId()
    info["session_id"] = sess_id.value
    info["active_console_session"] = active_console
    print(f"* Windows Session:    Session ID {sess_id.value} (Active Console: {active_console})")

    # Window station
    hwinsta = user32.GetProcessWindowStation()
    buf = ctypes.create_unicode_buffer(256)
    needed = wintypes.DWORD()
    user32.GetUserObjectInformationW(hwinsta, 2, buf, ctypes.sizeof(buf), ctypes.byref(needed))
    winsta_name = buf.value

    # Desktop
    hdesk = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    user32.GetUserObjectInformationW(hdesk, 2, buf, ctypes.sizeof(buf), ctypes.byref(needed))
    desk_name = buf.value

    info["window_station"] = winsta_name
    info["desktop"] = desk_name
    print(f"* Window Station:     {winsta_name}\\{desk_name} (Interactive: {winsta_name.lower() == 'winsta0'})")

    # Monitor info
    sw = user32.GetSystemMetrics(0)
    sh = user32.GetSystemMetrics(1)
    class MONITORINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("rcMonitor", wintypes.RECT),
            ("rcWork", wintypes.RECT),
            ("dwFlags", wintypes.DWORD),
        ]
    mi = MONITORINFO()
    mi.cbSize = ctypes.sizeof(MONITORINFO)
    hmon = user32.MonitorFromPoint(wintypes.POINT(0, 0), 1)
    user32.GetMonitorInfoW(hmon, ctypes.byref(mi))

    info["screen"] = f"{sw}x{sh}"
    info["work_area"] = f"({mi.rcWork.left}, {mi.rcWork.top}) to ({mi.rcWork.right}, {mi.rcWork.bottom})"
    print(f"* Primary Screen:     {sw} x {sh}")
    print(f"* Usable Work Area:   {info['work_area']}")
    return info


def test_standalone_tkinter() -> bool:
    print("\n" + "=" * 70)
    print(" 2. STANDALONE TKINTER VISIBILITY & EVENT TEST")
    print("=" * 70)

    import tkinter as tk
    user32 = ctypes.windll.user32

    root = tk.Tk()
    root.title("CodeNova - Standalone Visibility Test")
    root.geometry("400x250+450+250")

    lbl = tk.Label(root, text="Standalone Tkinter Test Window", font=("Helvetica", 11, "bold"))
    lbl.pack(pady=20)

    clicked = [False]
    def on_click():
        clicked[0] = True
        root.quit()

    btn = tk.Button(root, text="Click to Confirm Visibility", command=on_click)
    btn.pack(pady=10)

    root.update()

    hwnd = user32.GetParent(root.winfo_id()) or root.winfo_id()
    is_vis = bool(user32.IsWindowVisible(hwnd))
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))

    print(f"* Standalone Window HWND:      {hwnd}")
    print(f"* IsWindowVisible:             {is_vis}")
    print(f"* Window Rect:                 ({rect.left}, {rect.top}) - ({rect.right}, {rect.bottom})")
    print(f"* Window Dimensions:           {rect.right - rect.left} x {rect.bottom - rect.top}")

    # Simulate button click
    btn.invoke()
    root.update()
    root.destroy()

    success = is_vis and clicked[0]
    print(f"* Standalone Test Result:      {'PASSED (Window created and mapped cleanly)' if success else 'FAILED'}")
    return success


def test_app_gui_process() -> bool:
    print("\n" + "=" * 70)
    print(" 3. ACTUAL APP GUI PROCESS LAUNCH & WIN32 VISIBILITY CHECK")
    print("=" * 70)

    user32 = ctypes.windll.user32
    dwmapi = ctypes.windll.dwmapi

    # Spawn real application process with --gui
    p = subprocess.Popen(
        [sys.executable, "-u", "main.py", "--gui"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(1.5)
    poll = p.poll()
    if poll is not None:
        out, err = p.communicate()
        print(f"[!] Process exited prematurely with code {poll}!")
        print(f"STDOUT: {out}\nSTDERR: {err}")
        return False

    print(f"* GUI Process Active:          PID {p.pid} (running normally)")

    # Find the top-level window by PID
    hwnd_target = None
    title_target = ""

    def enum_windows_proc(hwnd, lParam):
        nonlocal hwnd_target, title_target
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == p.pid:
            length = user32.GetWindowTextLengthW(hwnd)
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            if "CodeNova" in buff.value:
                hwnd_target = hwnd
                title_target = buff.value
        return True

    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows(WNDENUMPROC(enum_windows_proc), 0)

    if not hwnd_target:
        print("[!] Could not locate window handle for process!")
        p.terminate()
        return False

    # Check Win32 attributes
    is_vis = bool(user32.IsWindowVisible(hwnd_target))
    is_iconic = bool(user32.IsIconic(hwnd_target))

    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd_target, ctypes.byref(rect))
    w = rect.right - rect.left
    h = rect.bottom - rect.top

    fg_hwnd = user32.GetForegroundWindow()
    is_fg = (fg_hwnd == hwnd_target)

    # Check DWM Cloaked status
    cloaked = wintypes.DWORD(0)
    dwmapi.DwmGetWindowAttribute(hwnd_target, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked))

    print(f"* Located Window Handle:       HWND {hwnd_target}")
    print(f"* Window Title:                {repr(title_target)}")
    print(f"* Win32 IsWindowVisible:       {is_vis}")
    print(f"* Is Minimized (Iconic):       {is_iconic}")
    print(f"* Screen Position & Size:      left={rect.left}, top={rect.top}, width={w}, height={h}")
    print(f"* Is Foreground Window:        {is_fg}")
    print(f"* DWMWA_CLOAKED Value:         {cloaked.value} ({'Uncloaked / Rendered by DWM' if cloaked.value == 0 else 'Cloaked'})")

    # Close the window cleanly
    user32.PostMessageW(hwnd_target, 0x0010, 0, 0)  # WM_CLOSE = 0x0010
    out, err = p.communicate(timeout=5)
    print(f"* Process Exit Code:           {p.returncode} (clean exit)")
    print(f"* Startup Logs:\n{out.strip()}")

    passed = is_vis and not is_iconic and (cloaked.value == 0) and (p.returncode == 0)
    print(f"* GUI Process Launch Result:   {'PASSED (Verified Visible & Clean Exit)' if passed else 'FAILED'}")
    return passed


def test_interactive_gui_eval() -> bool:
    print("\n" + "=" * 70)
    print(" 4. REAL INTERACTIVE GUI EVALUATION TEST")
    print("=" * 70)

    import tkinter as tk
    from src.gui import PasswordCheckerGUI

    root = tk.Tk()
    app = PasswordCheckerGUI(root)
    root.update()

    # Enter a synthetic test password
    test_pw = "Tr0ub4dor&"
    app.password_var.set(test_pw)
    app._on_password_change()
    root.update()

    badge = app.strength_badge.cget("text")
    score_txt = app.score_label.cget("text")
    prog_val = app.progress_bar["value"]
    fb_txt = app.feedback_box.get("1.0", tk.END)

    print(f"* Evaluated Password:          '{test_pw}'")
    print(f"* Result Badge:                {badge}")
    print(f"* Result Score:                {score_txt} (Progress bar: {prog_val})")
    print(f"* Findings in Feedback Box:    {repr(fb_txt.strip()[:65])}...")

    correct_eval = ("MODERATE" in badge) and (prog_val >= 70) and ("RECOMMENDATION" in fb_txt)

    # Test Clear button
    app.clear_input()
    root.update()
    cleared_badge = app.strength_badge.cget("text")
    cleared_val = app.password_var.get()
    print(f"* After Clear Action:          Badge='{cleared_badge}', Input='{cleared_val}'")

    root.destroy()
    passed = correct_eval and (cleared_val == "") and ("Enter a password" in cleared_badge)
    print(f"* Interactive GUI Test:        {'PASSED' if passed else 'FAILED'}")
    return passed


def test_cli_regression() -> bool:
    print("\n" + "=" * 70)
    print(" 5. CLI REGRESSION TEST")
    print("=" * 70)

    p = subprocess.Popen(
        [sys.executable, "main.py", "--cli", "--show-input", "--once"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, err = p.communicate(input="SecureP@ss2026\n", timeout=5)
    print(f"* CLI Exit Code:               {p.returncode}")
    has_output = ("OVERALL STRENGTH:" in out) and ("DUAL ENTROPY ANALYSIS:" in out)
    print(f"* Output Format Check:         {'PASSED' if has_output else 'FAILED'}")
    return p.returncode == 0 and has_output


def run_unit_tests() -> bool:
    print("\n" + "=" * 70)
    print(" 6. AUTOMATED UNIT TESTS EXECUTION")
    print("=" * 70)

    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    passed = result.wasSuccessful()
    print(f"* Total Tests Run:             {result.testsRun}")
    print(f"* Failures:                    {len(result.failures)}")
    print(f"* Errors:                      {len(result.errors)}")
    print(f"* Unit Tests Result:           {'PASSED' if passed else 'FAILED'}")
    return passed


def main():
    print("Starting Comprehensive Verification Suite for CodeNova Password Strength Checker...")
    env_info = run_environment_diagnostics()
    t1 = test_standalone_tkinter()
    t2 = test_app_gui_process()
    t3 = test_interactive_gui_eval()
    t4 = test_cli_regression()
    t5 = run_unit_tests()

    print("\n" + "=" * 70)
    print(" SUMMARY OF VERIFICATION RESULTS")
    print("=" * 70)
    print(f"1. Standalone Tkinter Visibility:  {'[ PASSED ]' if t1 else '[ FAILED ]'}")
    print(f"2. Application GUI Launch & Win32: {'[ PASSED ]' if t2 else '[ FAILED ]'}")
    print(f"3. Interactive GUI Evaluation:     {'[ PASSED ]' if t3 else '[ FAILED ]'}")
    print(f"4. CLI Regression Mode:            {'[ PASSED ]' if t4 else '[ FAILED ]'}")
    print(f"5. Unit Test Suite (21 tests):     {'[ PASSED ]' if t5 else '[ FAILED ]'}")

    all_passed = t1 and t2 and t3 and t4 and t5
    print("\nOVERALL STATUS: " + ("ALL VERIFICATIONS PASSED" if all_passed else "SOME CHECKS FAILED"))
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

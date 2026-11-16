"""Run 90 core/desktop checks; browser GUI checks live in verify_browser.js."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import tkinter as tk
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from Main import CATEGORIES, PasswordGeneratorApp, generate_password


def run_checks():
    checks = []

    def record(name, condition=True):
        if not condition:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})

    names = list(CATEGORIES)
    for mask in range(1, 16):
        selected = [CATEGORIES[name] for index, name in enumerate(names) if mask & (1 << index)]
        for length in (len(selected), 128):
            password = generate_password(length, selected)
            record(f"Desktop generator: mask {mask:04b}, length {length}",
                   len(password) == length and all(any(char in group for char in password) for group in selected)
                   and all(char in "".join(selected) for char in password))

    invalid = [(0, ["a"]), (-1, ["a"]), (129, ["a"]), (1.5, ["a"]),
               (True, ["a"]), (16, []), (16, None), (16, "abc"), (16, [""]), (1, ["a", "b"])]
    for length, categories in invalid:
        try:
            generate_password(length, categories)
        except ValueError:
            record(f"Desktop validation: length={length!r}, categories={categories!r}")
        else:
            raise AssertionError("Invalid input accepted")

    output = subprocess.run(["node", str(ROOT / "scripts" / "verify_web_matrix.mjs")],
                            check=True, capture_output=True, text=True, encoding="utf-8")
    checks.extend(json.loads(output.stdout))

    root = tk.Tk()
    root.withdraw()
    app = PasswordGeneratorApp(root)
    try:
        record("Desktop GUI: empty passphrase masked", app.passphrase_entry.cget("show") == "*")
        app._toggle_passphrase()
        record("Desktop GUI: reveal toggle updates label", app.reveal_button.cget("text") == "Hide" and app.passphrase_entry.cget("show") == "")
        app._toggle_passphrase()
        app._generate()
        record("Desktop GUI: generate populates password", len(app.password.get()) == 16)
        app.encrypted_text.insert("1.0", "old ciphertext")
        app._generate()
        record("Desktop GUI: generation clears stale ciphertext", not app.encrypted_text.get("1.0", "end").strip())
        app.length.set(0)
        app._generate()
        record("Desktop GUI: invalid length gives feedback", not app.password.get() and app.generator_status.cget("style") == "Error.TLabel")
        app.length.set(16)
        app._generate()
        app._encrypt()
        record("Desktop GUI: missing passphrase rejected without work", app._crypto_future is None and app.encryption_status.cget("style") == "Error.TLabel")
        app.passphrase.set("verification passphrase")
        release = threading.Event()

        def delayed_crypto(*_args):
            if not release.wait(5):
                raise RuntimeError("Verification worker timed out")
            return "verified ciphertext"

        with patch("Main.encrypt_password", delayed_crypto):
            app._encrypt()
            record("Desktop GUI: crypto disables conflicting actions", app.generate_button.instate(["disabled"]) and app.encrypt_button.instate(["disabled"]) and app.decrypt_button.instate(["disabled"]))
            original = app.password.get()
            app._generate()
            record("Desktop GUI: generating during crypto preserves snapshot", app.password.get() == original)
            heartbeat = []
            root.after(0, lambda: heartbeat.append(True))
            root.update()
            record("Desktop GUI: event loop responsive during worker", bool(heartbeat) and not app._crypto_future.done())
            release.set()
            deadline = time.monotonic() + 5
            while app._crypto_future is not None and time.monotonic() < deadline:
                root.update()
                time.sleep(0.005)
            record("Desktop GUI: completion restores controls and result", app._crypto_future is None and not app.encrypt_button.instate(["disabled"]) and app.encrypted_text.get("1.0", "end").strip() == "verified ciphertext")
    finally:
        app._close()
    assert len(checks) == 90, len(checks)
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results = {"checks": run_checks()}
    if args.output:
        args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Passed {len(results['checks'])} core and desktop checks.")

import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from Main import PasswordGeneratorApp


class DesktopGuiTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f"Desktop display unavailable: {error}")
        self.root.withdraw()
        self.app = PasswordGeneratorApp(self.root)

    def tearDown(self):
        if getattr(self, "app", None) is not None:
            self.app._close()

    def wait_for_crypto(self):
        deadline = time.monotonic() + 5
        while self.app._crypto_future is not None and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.005)
        self.assertIsNone(self.app._crypto_future, "Crypto did not complete")

    def test_async_encrypt_decrypt_round_trip(self):
        self.app._generate()
        password = self.app.password.get()
        self.app.passphrase.set("desktop test passphrase")
        self.app._encrypt()
        self.assertTrue(self.app.generate_button.instate(["disabled"]))
        self.wait_for_crypto()
        self.assertTrue(self.app.encrypted_text.get("1.0", "end").startswith("v1$"))
        self.app.password.set("")
        self.app._decrypt()
        self.wait_for_crypto()
        self.assertEqual(self.app.password.get(), password)
        self.assertFalse(self.app.decrypt_button.instate(["disabled"]))

    def test_worker_failure_restores_controls(self):
        self.app.passphrase.set("test passphrase")
        self.app.encrypted_text.insert("1.0", "malformed token")
        self.app._decrypt()
        self.wait_for_crypto()
        self.assertEqual(self.app.encryption_status.cget("style"), "Error.TLabel")
        self.assertFalse(self.app.encrypt_button.instate(["disabled"]))
        self.assertEqual(str(self.app.passphrase_entry.cget("state")), "normal")

    def test_invalid_generation_clears_stale_ciphertext(self):
        self.app.encrypted_text.insert("1.0", "stale ciphertext")
        self.app.length.set(0)
        self.app._generate()
        self.assertEqual(self.app.password.get(), "")
        self.assertEqual(self.app.encrypted_text.get("1.0", "end").strip(), "")

    def test_close_during_worker_cancels_gui_polling(self):
        release = threading.Event()
        started = threading.Event()
        def worker(*_args):
            started.set()
            release.wait(5)
            return "test ciphertext"
        try:
            with patch("Main.encrypt_password", worker):
                self.app.password.set("password")
                self.app.passphrase.set("passphrase")
                self.app._encrypt()
                future = self.app._crypto_future
                self.assertTrue(started.wait(5))
                self.app._close()
                self.assertIsNone(self.app._poll_id)
                self.app = None
                release.set()
                self.assertEqual(future.result(timeout=5), "test ciphertext")
        finally:
            release.set()

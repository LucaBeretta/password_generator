import unittest
import json
from pathlib import Path
import shutil
import subprocess
from unittest.mock import patch

from Main import (
    CATEGORIES,
    _fernet_for_passphrase,
    decrypt_password,
    encrypt_password,
    generate_password,
)


class GeneratePasswordTests(unittest.TestCase):
    def test_password_has_requested_length_and_each_selected_category(self):
        selected = [CATEGORIES["Lowercase"], CATEGORIES["Digits"]]

        password = generate_password(20, selected)

        self.assertEqual(len(password), 20)
        self.assertTrue(any(character in selected[0] for character in password))
        self.assertTrue(any(character in selected[1] for character in password))
        self.assertTrue(all(character in "".join(selected) for character in password))

    def test_rejects_lengths_outside_supported_range(self):
        for length in (0, 129):
            with self.subTest(length=length), self.assertRaises(ValueError):
                generate_password(length, [CATEGORIES["Lowercase"]])

    def test_rejects_non_integer_length(self):
        with self.assertRaises(ValueError):
            generate_password(12.5, [CATEGORIES["Lowercase"]])

    def test_rejects_invalid_character_sets(self):
        for categories in (None, "abc", [""], [1]):
            with self.subTest(categories=categories), self.assertRaises(ValueError):
                generate_password(12, categories)

    def test_encryption_round_trips_password(self):
        password = "local-only-P@ssw0rd"

        encrypted = encrypt_password(password, "correct horse battery staple")

        self.assertEqual(
            decrypt_password(encrypted, "correct horse battery staple"),
            password,
        )

    def test_decryption_reports_invalid_utf8_as_invalid_ciphertext(self):
        passphrase = "test passphrase"
        salt = b"\x00" * 16
        token = _fernet_for_passphrase(passphrase, salt).encrypt(b"\xff")
        encrypted = f"v1${salt.hex()}${token.decode('ascii')}"

        with self.assertRaisesRegex(ValueError, "encrypted password is invalid"):
            decrypt_password(encrypted, passphrase)

    def test_duplicate_categories_do_not_require_extra_length(self):
        self.assertIn(generate_password(1, ["abc", "abc"]), "abc")

    def test_malformed_tokens_are_rejected_before_expensive_key_derivation(self):
        with patch("Main._fernet_for_passphrase") as derive:
            for token in ("!", "", "gA==", "non-ascii-\u00e9"):
                with self.subTest(token=token), self.assertRaises(ValueError):
                    decrypt_password(f"v1${'00' * 16}${token}", "passphrase")
            derive.assert_not_called()

    @unittest.skipUnless(shutil.which("node"), "Node is needed for browser interoperability checks")
    def test_browser_and_desktop_ciphertexts_are_compatible(self):
        bridge = Path(__file__).resolve().parent / "scripts" / "crypto_bridge.mjs"
        for password in ("P@ssword-123", "\u00e9\U0001f510\u6f22\u5b57", "a" * 128):
            with self.subTest(length=len(password)):
                passphrase = "interoperability \u00e9 test"
                encrypted = encrypt_password(password, passphrase)
                result = subprocess.run(
                    ["node", str(bridge)],
                    input=json.dumps({"password": password, "encrypted": encrypted, "passphrase": passphrase}),
                    capture_output=True, text=True, encoding="utf-8", check=True,
                )
                data = json.loads(result.stdout)
                self.assertEqual(data["decrypted"], password)
                self.assertEqual(decrypt_password(data["encrypted"], passphrase), password)

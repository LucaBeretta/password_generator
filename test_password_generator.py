import unittest

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

import base64
import secrets
import string
import tkinter as tk
from tkinter import messagebox, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


CATEGORIES = {
    "Lowercase": string.ascii_lowercase,
    "Uppercase": string.ascii_uppercase,
    "Digits": string.digits,
    "Symbols": string.punctuation,
}
KDF_ITERATIONS = 600_000


def generate_password(length, selected_categories):
    if not selected_categories:
        raise ValueError("Select at least one character type.")
    if length < len(selected_categories):
        raise ValueError(
            "The password length must be at least the number of selected character types."
        )

    password = [secrets.choice(category) for category in selected_categories]
    all_characters = "".join(selected_categories)
    password.extend(
        secrets.choice(all_characters) for _ in range(length - len(password))
    )
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def _fernet_for_passphrase(passphrase, salt):
    key_material = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    ).derive(passphrase.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key_material))


def encrypt_password(password, passphrase):
    if not passphrase:
        raise ValueError("Enter a passphrase before encrypting.")

    salt = secrets.token_bytes(16)
    token = _fernet_for_passphrase(passphrase, salt).encrypt(
        password.encode("utf-8")
    )
    return f"v1${salt.hex()}${token.decode('ascii')}"


def decrypt_password(encrypted_password, passphrase):
    if not passphrase:
        raise ValueError("Enter the passphrase used to encrypt the password.")

    try:
        version, salt_hex, token = encrypted_password.split("$", 2)
        salt = bytes.fromhex(salt_hex)
    except ValueError as error:
        raise ValueError("The encrypted password format is invalid.") from error

    if version != "v1" or len(salt) != 16:
        raise ValueError("The encrypted password format is invalid.")

    try:
        decrypted = _fernet_for_passphrase(passphrase, salt).decrypt(
            token.encode("ascii")
        )
    except (InvalidToken, UnicodeEncodeError) as error:
        raise ValueError(
            "The passphrase is incorrect or the encrypted password is invalid."
        ) from error
    return decrypted.decode("utf-8")


class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.minsize(520, 500)

        self.length = tk.IntVar(value=16)
        self.category_vars = {
            name: tk.BooleanVar(value=True) for name in CATEGORIES
        }
        self.password = tk.StringVar()
        self.passphrase = tk.StringVar()

        self._build_ui()

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=16)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Password length").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(
            frame, from_=1, to=256, textvariable=self.length, width=8
        ).grid(row=0, column=1, sticky="e")

        options = ttk.LabelFrame(frame, text="Character types", padding=8)
        options.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        for column, (name, variable) in enumerate(self.category_vars.items()):
            ttk.Checkbutton(options, text=name, variable=variable).grid(
                row=0, column=column, padx=(0, 10), sticky="w"
            )

        ttk.Button(frame, text="Generate password", command=self._generate).grid(
            row=2, column=0, columnspan=2, sticky="ew", pady=12
        )

        ttk.Label(frame, text="Password").grid(
            row=3, column=0, columnspan=2, sticky="w"
        )
        password_entry = ttk.Entry(
            frame, textvariable=self.password, state="readonly"
        )
        password_entry.grid(row=4, column=0, sticky="ew", pady=(4, 0))
        ttk.Button(frame, text="Copy", command=self._copy_password).grid(
            row=4, column=1, padx=(8, 0), pady=(4, 0)
        )

        encryption = ttk.LabelFrame(frame, text="Encryption", padding=10)
        encryption.grid(
            row=5, column=0, columnspan=2, sticky="nsew", pady=(16, 0)
        )
        encryption.columnconfigure(0, weight=1)

        ttk.Label(encryption, text="Passphrase").grid(row=0, column=0, sticky="w")
        ttk.Entry(
            encryption, textvariable=self.passphrase, show="*"
        ).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 10))
        ttk.Button(
            encryption, text="Encrypt password", command=self._encrypt
        ).grid(row=2, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(
            encryption, text="Decrypt to password", command=self._decrypt
        ).grid(row=2, column=1, sticky="ew", padx=(4, 0))

        ttk.Label(encryption, text="Encrypted password").grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(12, 0)
        )
        self.encrypted_text = tk.Text(encryption, height=4, wrap="word")
        self.encrypted_text.grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(4, 0)
        )

    def _generate(self):
        try:
            length = self.length.get()
            selected = [
                CATEGORIES[name]
                for name, variable in self.category_vars.items()
                if variable.get()
            ]
            self.password.set(generate_password(length, selected))
        except (tk.TclError, ValueError) as error:
            messagebox.showerror("Cannot generate password", str(error))

    def _copy_password(self):
        password = self.password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)

    def _encrypt(self):
        password = self.password.get()
        if not password:
            messagebox.showerror("Cannot encrypt", "Generate a password first.")
            return
        try:
            encrypted = encrypt_password(password, self.passphrase.get())
        except ValueError as error:
            messagebox.showerror("Cannot encrypt", str(error))
            return

        self.encrypted_text.delete("1.0", "end")
        self.encrypted_text.insert("1.0", encrypted)

    def _decrypt(self):
        encrypted = self.encrypted_text.get("1.0", "end").strip()
        try:
            self.password.set(decrypt_password(encrypted, self.passphrase.get()))
        except ValueError as error:
            messagebox.showerror("Cannot decrypt", str(error))


def main():
    root = tk.Tk()
    PasswordGeneratorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

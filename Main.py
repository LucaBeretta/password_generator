import base64
import binascii
from concurrent.futures import ThreadPoolExecutor
import secrets
import string
import tkinter as tk
from tkinter import ttk
from typing import Sequence

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


CATEGORIES = {
    "Lowercase": string.ascii_lowercase,
    "Uppercase": string.ascii_uppercase,
    "Digits": string.digits,
    "Symbols": string.punctuation,
}
MIN_PASSWORD_LENGTH = 1
MAX_PASSWORD_LENGTH = 128
KDF_ITERATIONS = 600_000


def generate_password(length: int, selected_categories: Sequence[str]) -> str:
    if (
        not isinstance(length, int)
        or isinstance(length, bool)
        or not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH
    ):
        raise ValueError(
            f"Password length must be between {MIN_PASSWORD_LENGTH} and "
            f"{MAX_PASSWORD_LENGTH} characters."
        )

    if isinstance(selected_categories, (str, bytes)):
        raise ValueError("Select categories as separate character sets.")

    try:
        categories = tuple(selected_categories)
    except TypeError as error:
        raise ValueError("Select at least one valid character type.") from error

    if not categories:
        raise ValueError("Select at least one character type.")
    if any(not isinstance(category, str) or not category for category in categories):
        raise ValueError("Character types must be non-empty strings.")
    categories = tuple(dict.fromkeys(categories))
    if length < len(categories):
        raise ValueError(
            "The password length must be at least the number of selected character types."
        )

    password = [secrets.choice(category) for category in categories]
    all_characters = "".join(categories)
    password.extend(
        secrets.choice(all_characters) for _ in range(length - len(password))
    )
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def _fernet_for_passphrase(passphrase: str, salt: bytes) -> Fernet:
    key_material = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    ).derive(passphrase.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key_material))


def encrypt_password(password: str, passphrase: str) -> str:
    if not passphrase:
        raise ValueError("Enter a passphrase before encrypting.")

    salt = secrets.token_bytes(16)
    token = _fernet_for_passphrase(passphrase, salt).encrypt(
        password.encode("utf-8")
    )
    return f"v1${salt.hex()}${token.decode('ascii')}"


def decrypt_password(encrypted_password: str, passphrase: str) -> str:
    if not passphrase:
        raise ValueError("Enter the passphrase used to encrypt the password.")

    try:
        version, salt_hex, token = encrypted_password.split("$", 2)
        salt = bytes.fromhex(salt_hex)
    except ValueError as error:
        raise ValueError("The encrypted password format is invalid.") from error

    if version != "v1" or len(salt_hex) != 32 or len(salt) != 16:
        raise ValueError("The encrypted password format is invalid.")

    try:
        token_bytes = token.encode("ascii")
        raw_token = base64.b64decode(token_bytes, altchars=b"-_", validate=True)
        if len(raw_token) < 73 or raw_token[0] != 0x80 or (len(raw_token) - 57) % 16:
            raise InvalidToken
        decrypted = _fernet_for_passphrase(passphrase, salt).decrypt(
            token_bytes
        )
        return decrypted.decode("utf-8")
    except (InvalidToken, binascii.Error, UnicodeDecodeError, UnicodeEncodeError) as error:
        raise ValueError(
            "The passphrase is incorrect or the encrypted password is invalid."
        ) from error


class PasswordGeneratorApp:
    COLORS = {
        "background": "#f3f5fa",
        "card": "#ffffff",
        "text": "#18243a",
        "muted": "#69758b",
        "accent": "#4f46e5",
        "accent_hover": "#4338ca",
        "border": "#e0e5ef",
        "field": "#f8f9fc",
        "success": "#16845b",
        "error": "#c2414b",
    }

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("620x790")
        self.root.minsize(540, 720)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="password-crypto")
        self._crypto_future = None
        self._poll_id = None
        self.root.protocol("WM_DELETE_WINDOW", self._close)

        self.length = tk.IntVar(value=16)
        self.category_vars = {
            name: tk.BooleanVar(value=True) for name in CATEGORIES
        }
        self.password = tk.StringVar()
        self.passphrase = tk.StringVar()
        self.show_passphrase = tk.BooleanVar(value=False)
        self.generator_notice = tk.StringVar(
            value="Choose a length and character types, then generate."
        )
        self.encryption_notice = tk.StringVar(
            value="Encryption is optional. Keep your passphrase safe."
        )

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self) -> None:
        colors = self.COLORS
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        self.root.configure(background=colors["background"])
        style.configure(
            "App.TFrame",
            background=colors["background"],
        )
        style.configure("Card.TFrame", background=colors["card"])
        style.configure(
            "TLabel",
            background=colors["background"],
            foreground=colors["text"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Eyebrow.TLabel",
            background=colors["background"],
            foreground=colors["accent"],
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "Title.TLabel",
            background=colors["background"],
            foreground=colors["text"],
            font=("Segoe UI", 20, "bold"),
        )
        style.configure(
            "CardTitle.TLabel",
            background=colors["card"],
            foreground=colors["text"],
            font=("Segoe UI", 13, "bold"),
        )
        style.configure(
            "CardBody.TLabel",
            background=colors["card"],
            foreground=colors["muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Card.TCheckbutton",
            background=colors["card"],
            foreground=colors["text"],
            font=("Segoe UI", 10),
            padding=(2, 1),
        )
        style.map(
            "Card.TCheckbutton",
            background=[("active", colors["card"])],
            foreground=[("disabled", colors["muted"])],
        )
        style.configure(
            "TEntry",
            fieldbackground=colors["field"],
            foreground=colors["text"],
            bordercolor=colors["border"],
            padding=(10, 6),
        )
        style.configure(
            "TSpinbox",
            fieldbackground=colors["field"],
            foreground=colors["text"],
            bordercolor=colors["border"],
            padding=(8, 5),
            arrowsize=12,
        )
        style.configure(
            "TButton",
            font=("Segoe UI", 9, "bold"),
            padding=(12, 7),
        )
        style.configure(
            "Primary.TButton",
            background=colors["accent"],
            foreground="#ffffff",
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[
                ("pressed", colors["accent_hover"]),
                ("active", colors["accent_hover"]),
            ],
        )
        style.configure(
            "Secondary.TButton",
            background=colors["field"],
            foreground=colors["text"],
            borderwidth=0,
        )
        style.map(
            "Secondary.TButton",
            background=[("active", colors["border"])],
        )
        style.configure(
            "Status.TLabel",
            background=colors["card"],
            foreground=colors["muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Success.TLabel",
            background=colors["card"],
            foreground=colors["success"],
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "Error.TLabel",
            background=colors["card"],
            foreground=colors["error"],
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "Footer.TLabel",
            background=colors["background"],
            foreground=colors["muted"],
            font=("Segoe UI", 9),
        )

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, style="App.TFrame", padding=(20, 12))
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)

        ttk.Label(
            frame, text="SECURE PASSWORD TOOL", style="Eyebrow.TLabel"
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            frame, text="Password Generator", style="Title.TLabel"
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        generator = ttk.Frame(frame, style="Card.TFrame", padding=14)
        generator.grid(row=3, column=0, sticky="ew")
        generator.columnconfigure(0, weight=4)
        generator.columnconfigure(1, weight=1)

        ttk.Label(
            generator, text="Create a password", style="CardTitle.TLabel"
        ).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(
            generator,
            text="Choose the length and character types to include.",
            style="CardBody.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(3, 8))

        ttk.Label(
            generator, text="Password length", style="CardBody.TLabel"
        ).grid(row=2, column=0, sticky="w")
        self.length_spinbox = ttk.Spinbox(
            generator,
            from_=MIN_PASSWORD_LENGTH,
            to=MAX_PASSWORD_LENGTH,
            textvariable=self.length,
            width=8,
            justify="center",
        )
        self.length_spinbox.grid(row=2, column=1, sticky="e")
        self.length_spinbox.bind("<Return>", self._generate_shortcut)

        ttk.Label(
            generator, text="Character types", style="CardBody.TLabel"
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 2))
        categories = ttk.Frame(generator, style="Card.TFrame")
        categories.grid(row=4, column=0, columnspan=2, sticky="ew")
        categories.columnconfigure(0, weight=1)
        categories.columnconfigure(1, weight=1)
        category_labels = {
            "Lowercase": "Lowercase  a-z",
            "Uppercase": "Uppercase  A-Z",
            "Digits": "Numbers  0-9",
            "Symbols": "Symbols  !@#",
        }
        for index, (name, variable) in enumerate(self.category_vars.items()):
            ttk.Checkbutton(
                categories,
                text=category_labels[name],
                variable=variable,
                style="Card.TCheckbutton",
            ).grid(
                row=index // 2,
                column=index % 2,
                sticky="w",
                padx=(0, 8),
            )

        self.generate_button = ttk.Button(
            generator,
            text="Generate password",
            style="Primary.TButton",
            command=self._generate,
        )
        self.generate_button.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(8, 10))

        ttk.Label(
            generator, text="Your password", style="CardBody.TLabel"
        ).grid(row=6, column=0, columnspan=2, sticky="w")
        self.password_entry = ttk.Entry(
            generator,
            textvariable=self.password,
            state="readonly",
            font=("Consolas", 12),
        )
        self.password_entry.grid(row=7, column=0, sticky="ew", pady=(5, 0))
        ttk.Button(
            generator,
            text="Copy password",
            style="Secondary.TButton",
            command=self._copy_password,
        ).grid(row=7, column=1, sticky="ew", padx=(8, 0), pady=(5, 0))
        self.generator_status = ttk.Label(
            generator,
            textvariable=self.generator_notice,
            style="Status.TLabel",
            wraplength=480,
        )
        self.generator_status.grid(
            row=8, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )

        encryption = ttk.Frame(frame, style="Card.TFrame", padding=14)
        encryption.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        encryption.columnconfigure(0, weight=1)
        encryption.columnconfigure(1, weight=1)

        ttk.Label(
            encryption, text="Encrypt or decrypt", style="CardTitle.TLabel"
        ).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(
            encryption,
            text="Use a passphrase you can remember. You need it to decrypt.",
            style="CardBody.TLabel",
            wraplength=450,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(3, 8))
        ttk.Label(
            encryption, text="Passphrase", style="CardBody.TLabel"
        ).grid(row=2, column=0, sticky="w")
        self.reveal_button = ttk.Button(
            encryption,
            text="Show",
            style="Secondary.TButton",
            command=self._toggle_passphrase,
        )
        self.reveal_button.grid(
            row=2, column=1, sticky="e"
        )
        self.passphrase_entry = ttk.Entry(
            encryption,
            textvariable=self.passphrase,
            show="*",
        )
        self.passphrase_entry.grid(
            row=3, column=0, columnspan=2, sticky="ew", pady=(4, 8)
        )
        self.encrypt_button = ttk.Button(
            encryption,
            text="Encrypt password",
            style="Primary.TButton",
            command=self._encrypt,
        )
        self.encrypt_button.grid(row=4, column=0, sticky="ew", padx=(0, 4))
        self.decrypt_button = ttk.Button(
            encryption,
            text="Decrypt to password",
            style="Secondary.TButton",
            command=self._decrypt,
        )
        self.decrypt_button.grid(row=4, column=1, sticky="ew", padx=(4, 0))

        ttk.Label(
            encryption, text="Encrypted password", style="CardBody.TLabel"
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(14, 4))
        self.encrypted_text = tk.Text(
            encryption,
            width=48,
            height=2,
            wrap="word",
            font=("Consolas", 9),
            background=self.COLORS["field"],
            foreground=self.COLORS["text"],
            insertbackground=self.COLORS["text"],
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=self.COLORS["border"],
            highlightcolor=self.COLORS["accent"],
            padx=10,
            pady=8,
        )
        self.encrypted_text.grid(
            row=6, column=0, columnspan=2, sticky="ew"
        )
        self.copy_encrypted_button = ttk.Button(
            encryption,
            text="Copy encrypted password",
            style="Secondary.TButton",
            command=self._copy_encrypted,
        )
        self.copy_encrypted_button.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self.encryption_status = ttk.Label(
            encryption,
            textvariable=self.encryption_notice,
            style="Status.TLabel",
            wraplength=480,
        )
        self.encryption_status.grid(
            row=8, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )

        ttk.Label(
            frame,
            text="Generated locally on your device. Nothing is sent online.",
            style="Footer.TLabel",
        ).grid(row=5, column=0, sticky="w", pady=(8, 0))

        self.root.bind("<Control-Return>", self._generate_shortcut)

    def _generate_shortcut(self, _event=None):
        self._generate()
        return "break"

    def _close(self):
        if self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None
        self._executor.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()

    def _set_crypto_busy(self, busy):
        state = "disabled" if busy else "normal"
        for widget in (self.generate_button, self.encrypt_button, self.decrypt_button,
                       self.copy_encrypted_button, self.passphrase_entry):
            widget.configure(state=state)
        self.encrypted_text.configure(state=state)

    def _start_crypto(self, operation, value, passphrase):
        if self._crypto_future is not None:
            return
        if not passphrase:
            self._set_notice(self.encryption_status, self.encryption_notice, "Enter a passphrase first.", "error")
            return
        self._set_crypto_busy(True)
        self._set_notice(self.encryption_status, self.encryption_notice, "Encrypting…" if operation == "encrypt" else "Decrypting…")
        function = encrypt_password if operation == "encrypt" else decrypt_password
        # Workers receive plain strings; only the Tk thread touches widgets.
        self._crypto_future = self._executor.submit(function, value, passphrase)
        self._poll_id = self.root.after(15, self._poll_crypto, operation)

    def _poll_crypto(self, operation):
        self._poll_id = None
        if not self._crypto_future.done():
            self._poll_id = self.root.after(15, self._poll_crypto, operation)
            return
        future, self._crypto_future = self._crypto_future, None
        self._set_crypto_busy(False)
        try:
            result = future.result()
        except Exception as error:
            message = str(error) if isinstance(error, ValueError) else "Could not complete the operation. Try again."
            self._set_notice(self.encryption_status, self.encryption_notice, message, "error")
            return
        if operation == "encrypt":
            self.encrypted_text.delete("1.0", "end")
            self.encrypted_text.insert("1.0", result)
            message = "Password encrypted. Keep the passphrase to decrypt it later."
        else:
            self.password.set(result)
            self._set_notice(self.generator_status, self.generator_notice, "Password decrypted and restored to the password field.", "success")
            message = "Password decrypted successfully."
        self._set_notice(self.encryption_status, self.encryption_notice, message, "success")

    def _set_notice(
        self,
        label: ttk.Label,
        variable: tk.StringVar,
        message: str,
        kind: str = "info",
    ) -> None:
        variable.set(message)
        style = {
            "info": "Status.TLabel",
            "success": "Success.TLabel",
            "error": "Error.TLabel",
        }[kind]
        label.configure(style=style)

    def _generate(self) -> None:
        if self._crypto_future is not None:
            return
        try:
            length = self.length.get()
            selected = [
                CATEGORIES[name]
                for name, variable in self.category_vars.items()
                if variable.get()
            ]
            self.password.set(generate_password(length, selected))
        except (tk.TclError, ValueError) as error:
            self.password.set("")
            self.encrypted_text.delete("1.0", "end")
            self._set_notice(
                self.generator_status,
                self.generator_notice,
                str(error),
                "error",
            )
            return

        self.encrypted_text.delete("1.0", "end")
        self._set_notice(
            self.generator_status,
            self.generator_notice,
            "Password generated. Copy it or encrypt it below.",
            "success",
        )
        self._set_notice(
            self.encryption_status,
            self.encryption_notice,
            "A new password is ready to encrypt.",
        )

    def _copy_password(self) -> None:
        password = self.password.get()
        if not password:
            self._set_notice(
                self.generator_status,
                self.generator_notice,
                "Generate a password before copying it.",
                "error",
            )
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
        except tk.TclError as error:
            self._set_notice(
                self.generator_status,
                self.generator_notice,
                f"Could not copy password: {error}",
                "error",
            )
            return
        self._set_notice(
            self.generator_status,
            self.generator_notice,
            "Password copied to the clipboard.",
            "success",
        )

    def _copy_encrypted(self) -> None:
        encrypted = self.encrypted_text.get("1.0", "end").strip()
        if not encrypted:
            self._set_notice(
                self.encryption_status,
                self.encryption_notice,
                "Encrypt a password or paste encrypted text first.",
                "error",
            )
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(encrypted)
        except tk.TclError as error:
            self._set_notice(
                self.encryption_status,
                self.encryption_notice,
                f"Could not copy encrypted password: {error}",
                "error",
            )
            return
        self._set_notice(
            self.encryption_status,
            self.encryption_notice,
            "Encrypted password copied to the clipboard.",
            "success",
        )

    def _toggle_passphrase(self) -> None:
        visible = not self.show_passphrase.get()
        self.show_passphrase.set(visible)
        self.passphrase_entry.configure(show="" if visible else "*")
        self.reveal_button.configure(text="Hide" if visible else "Show")

    def _encrypt(self) -> None:
        password = self.password.get()
        if not password:
            self._set_notice(
                self.encryption_status,
                self.encryption_notice,
                "Generate a password first.",
                "error",
            )
            return
        self._start_crypto("encrypt", password, self.passphrase.get())

    def _decrypt(self) -> None:
        encrypted = self.encrypted_text.get("1.0", "end").strip()
        self._start_crypto("decrypt", encrypted, self.passphrase.get())


def main() -> None:
    root = tk.Tk()
    PasswordGeneratorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

const ITERATIONS = 600_000;
const CATEGORY_CHARS = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
};
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function randomBytes(length) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Secure random generation is unavailable in this browser.");
  }
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function randomIndex(max) {
  const limit = Math.floor(256 / max) * max;
  let value;
  do {
    value = randomBytes(1)[0];
  } while (value >= limit);
  return value % max;
}

function secureShuffle(values) {
  for (let i = values.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    [values[i], values[j]] = [values[j], values[i]];
  }
  return values;
}

export function generatePassword(length, selectedCategories) {
  const categories = [...new Set(selectedCategories)].map((name) => CATEGORY_CHARS[name]);
  if (!categories.length || categories.some((characters) => !characters)) {
    throw new Error("Select at least one valid character type.");
  }
  if (!Number.isInteger(length) || length < categories.length || length > 128) {
    throw new Error(`Choose a length from ${categories.length} to 128 characters.`);
  }
  const allCharacters = categories.join("");
  const password = categories.map((characters) => characters[randomIndex(characters.length)]);
  while (password.length < length) {
    password.push(allCharacters[randomIndex(allCharacters.length)]);
  }
  return secureShuffle(password).join("");
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToBytes(value) {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) throw new Error("invalid token");
  const unpadded = value.replace(/=+$/g, "");
  const base64 = unpadded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error("invalid salt");
  return Uint8Array.from(hex.match(/.{2}/g), (part) => parseInt(part, 16));
}

function requireSecureCrypto() {
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    throw new Error("Encryption needs a secure HTTPS page. Open this site over HTTPS to use encryption and decryption.");
  }
}

async function deriveFernetKeys(passphrase, salt) {
  const material = await crypto.subtle.importKey(
    "raw", textEncoder.encode(passphrase), "PBKDF2", false, ["deriveBits"],
  );
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS },
    material,
    256,
  ));
  const signingKey = await crypto.subtle.importKey(
    "raw", bits.slice(0, 16), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"],
  );
  const encryptionKey = await crypto.subtle.importKey(
    "raw", bits.slice(16), { name: "AES-CBC" }, false, ["encrypt", "decrypt"],
  );
  return { signingKey, encryptionKey };
}

export async function encryptPassword(password, passphrase) {
  requireSecureCrypto();
  if (!passphrase) throw new Error("Enter a passphrase before encrypting.");
  if (!password) throw new Error("Generate a password first.");

  const salt = randomBytes(16);
  const iv = randomBytes(16);
  const { signingKey, encryptionKey } = await deriveFernetKeys(passphrase, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CBC", iv }, encryptionKey, textEncoder.encode(password),
  ));
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = new Uint8Array(25 + ciphertext.length);
  payload[0] = 0x80;
  new DataView(payload.buffer).setBigUint64(1, BigInt(timestamp), false);
  payload.set(iv, 9);
  payload.set(ciphertext, 25);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", signingKey, payload));
  const token = new Uint8Array(payload.length + signature.length);
  token.set(payload);
  token.set(signature, payload.length);
  return `v1$${bytesToHex(salt)}$${bytesToBase64Url(token)}`;
}

export async function decryptPassword(encrypted, passphrase) {
  requireSecureCrypto();
  if (!passphrase) throw new Error("Enter the passphrase used to encrypt the password.");
  try {
    const parts = encrypted.trim().split("$");
    if (parts.length !== 3 || parts[0] !== "v1") throw new Error("format");
    const salt = hexToBytes(parts[1]);
    const token = base64UrlToBytes(parts[2]);
    if (token.length < 73 || (token.length - 57) % 16 !== 0 || token[0] !== 0x80) {
      throw new Error("token");
    }

    const signedLength = token.length - 32;
    const signed = token.slice(0, signedLength);
    const signature = token.slice(signedLength);
    const { signingKey, encryptionKey } = await deriveFernetKeys(passphrase, salt);
    const valid = await crypto.subtle.verify("HMAC", signingKey, signature, signed);
    if (!valid) throw new Error("signature");
    const iv = signed.slice(9, 25);
    const ciphertext = signed.slice(25);
    const cleartext = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, encryptionKey, ciphertext);
    return textDecoder.decode(cleartext);
  } catch {
    throw new Error("The passphrase is incorrect or the encrypted password is invalid.");
  }
}

function setStatus(element, message, kind = "") {
  element.textContent = message;
  if (kind) element.dataset.kind = kind;
  else delete element.dataset.kind;
}

async function copyText(value) {
  if (!value) throw new Error("There is nothing to copy yet.");
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const helper = document.createElement("textarea");
  helper.value = value;
  helper.setAttribute("readonly", "");
  helper.style.position = "fixed";
  helper.style.opacity = "0";
  document.body.append(helper);
  helper.select();
  const copied = document.execCommand("copy");
  helper.remove();
  if (!copied) throw new Error("Clipboard access is unavailable. Select and copy the text instead.");
}

if (typeof document !== "undefined") {
  const $ = (selector) => document.querySelector(selector);
  const passwordOutput = $("#password");
  const lengthInput = $("#length");
  const lengthValue = $("#length-value");
  const generatorStatus = $("#generator-status");
  const vaultStatus = $("#vault-status");

  function updateLength() {
    lengthValue.value = lengthInput.value;
    lengthValue.textContent = lengthInput.value;
    const progress = ((Number(lengthInput.value) - Number(lengthInput.min)) /
      (Number(lengthInput.max) - Number(lengthInput.min))) * 100;
    lengthInput.style.background = `linear-gradient(90deg, var(--blue) 0%, var(--blue) ${progress}%, #e8eaf1 ${progress}%)`;
  }
  updateLength();
  lengthInput.addEventListener("input", updateLength);

  $("#generate").addEventListener("click", () => {
    const checked = [...document.querySelectorAll('input[name="category"]:checked')].map((input) => input.value);
    try {
      passwordOutput.textContent = generatePassword(Number(lengthInput.value), checked);
      $("#copy-password").disabled = false;
      setStatus(generatorStatus, "Password ready. It was generated on this device.", "success");
      setStatus(vaultStatus, "A new password is ready to encrypt.");
    } catch (error) {
      passwordOutput.textContent = "Tap generate to begin";
      $("#copy-password").disabled = true;
      setStatus(generatorStatus, error.message, "error");
    }
  });

  $("#copy-password").addEventListener("click", async () => {
    try {
      await copyText(passwordOutput.textContent);
      setStatus(generatorStatus, "Password copied to the clipboard.", "success");
    } catch (error) {
      setStatus(generatorStatus, error.message, "error");
    }
  });

  $("#toggle-passphrase").addEventListener("click", (event) => {
    const passphrase = $("#passphrase");
    const visible = passphrase.type === "password";
    passphrase.type = visible ? "text" : "password";
    event.currentTarget.textContent = visible ? "Hide" : "Show";
    event.currentTarget.setAttribute("aria-label", `${visible ? "Hide" : "Show"} passphrase`);
    event.currentTarget.setAttribute("aria-pressed", String(visible));
  });

  $("#encrypt").addEventListener("click", async () => {
    try {
      $("#encrypted").value = await encryptPassword(passwordOutput.textContent === "Tap generate to begin" ? "" : passwordOutput.textContent, $("#passphrase").value);
      setStatus(vaultStatus, "Password encrypted. Keep the passphrase to decrypt it later.", "success");
    } catch (error) {
      setStatus(vaultStatus, error.message, "error");
    }
  });

  $("#decrypt").addEventListener("click", async () => {
    try {
      const password = await decryptPassword($("#encrypted").value, $("#passphrase").value);
      passwordOutput.textContent = password;
      $("#copy-password").disabled = false;
      setStatus(generatorStatus, "Password decrypted and restored above.", "success");
      setStatus(vaultStatus, "Password decrypted successfully.", "success");
    } catch (error) {
      setStatus(vaultStatus, error.message, "error");
    }
  });

  $("#copy-encrypted").addEventListener("click", async () => {
    try {
      await copyText($("#encrypted").value.trim());
      setStatus(vaultStatus, "Encrypted text copied to the clipboard.", "success");
    } catch (error) {
      setStatus(vaultStatus, error.message, "error");
    }
  });

  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    const note = $("#security-note");
    const warning = document.createElement("p");
    warning.className = "security-warning";
    warning.setAttribute("role", "status");
    warning.textContent = "Encryption is unavailable here. Encryption and decryption require a secure HTTPS page; no weaker fallback is used.";
    note.after(warning);
  }
}

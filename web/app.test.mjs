import assert from "node:assert/strict";
import { test } from "node:test";
import { generatePassword, encryptPassword, decryptPassword, copyText } from "./app.mjs";

test("passwords cover selected categories at supported boundaries", () => {
  for (const length of [4, 20, 128]) {
    const password = generatePassword(length, ["lowercase", "uppercase", "digits", "symbols"]);
    assert.equal(password.length, length);
    for (const pattern of [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/]) {
      assert.match(password, pattern);
    }
  }
});

test("invalid categories and lengths fail promptly", () => {
  for (const categories of [null, "digits", [], ["toString"], ["__proto__"], [1], ["unknown"]]) {
    assert.throws(() => generatePassword(20, categories), /character type/);
  }
  for (const length of [0, 129, 2.5, NaN, true]) {
    assert.throws(() => generatePassword(length, ["digits"]), /length/);
  }
  assert.match(generatePassword(1, ["digits", "digits"]), /^\d$/);
});

test("randomness is batched and rejected bytes are skipped", () => {
  const original = crypto.getRandomValues;
  let calls = 0;
  crypto.getRandomValues = (bytes) => {
    calls += 1;
    bytes.fill(255);
    bytes[0] = 7;
    return bytes;
  };
  try {
    assert.equal(generatePassword(2, ["digits"]), "77");
    assert.equal(calls, 2);
  } finally {
    crypto.getRandomValues = original;
  }
});

test("encryption round trips Unicode and rejects wrong passphrases and tampering", async () => {
  globalThis.isSecureContext = true;
  const password = "Päss🔐word";
  const encrypted = await encryptPassword(password, "test passphrase");
  assert.equal(await decryptPassword(encrypted, "test passphrase"), password);
  await assert.rejects(decryptPassword(encrypted, "wrong"), /incorrect/);
  const parts = encrypted.split("$");
  parts[1] = "00".repeat(16);
  await assert.rejects(decryptPassword(parts.join("$"), "test passphrase"), /invalid/);
});

test("clipboard fallback cleans up and restores focus on success and failure", async () => {
  const descriptors = Object.fromEntries(["document", "navigator"].map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  try {
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: {} });
    for (const outcome of [true, false, "throw"]) {
      let removed = false;
      let focused = false;
      const helper = { value: "", style: {}, setAttribute() {}, select() {}, remove() { removed = true; } };
      Object.defineProperty(globalThis, "document", {
        configurable: true,
        value: {
          activeElement: { focus() { focused = true; } },
          createElement() { return helper; },
          body: { append() {} },
          execCommand() {
            if (outcome === "throw") throw new Error("Clipboard denied");
            return outcome;
          },
        },
      });
      if (outcome === true) await copyText("test-password");
      else await assert.rejects(copyText("test-password"), /Clipboard/);
      assert.equal(helper.value, "test-password");
      assert.equal(removed, true);
      assert.equal(focused, true);
    }
  } finally {
    for (const [name, descriptor] of Object.entries(descriptors)) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
});

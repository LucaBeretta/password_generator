import assert from "node:assert/strict";
import { generatePassword } from "../web/app.mjs";

const checks = [];
const names = ["lowercase", "uppercase", "digits", "symbols"];
const patterns = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/];
for (let mask = 1; mask < 16; mask++) {
  const selected = names.filter((_, index) => mask & (1 << index));
  for (const length of [selected.length, 128]) {
    const password = generatePassword(length, selected);
    assert.equal(password.length, length);
    for (let index = 0; index < 4; index++) {
      if (mask & (1 << index)) assert.match(password, patterns[index]);
      else assert.doesNotMatch(password, patterns[index]);
    }
    checks.push({ name: `Browser generator: ${selected.join("+")}, length ${length}`, passed: true });
  }
}
for (const [length, categories, label] of [
  [0, ["digits"], "zero length"], [-1, ["digits"], "negative length"],
  [129, ["digits"], "oversized length"], [1.5, ["digits"], "fractional length"],
  [true, ["digits"], "boolean length"], [16, [], "empty categories"],
  [16, null, "null categories"], [16, "digits", "string categories"],
  [16, ["__proto__"], "prototype property"], [1, ["digits", "uppercase"], "insufficient length"],
]) {
  assert.throws(() => generatePassword(length, categories));
  checks.push({ name: `Browser validation: ${label}`, passed: true });
}
console.log(JSON.stringify(checks));

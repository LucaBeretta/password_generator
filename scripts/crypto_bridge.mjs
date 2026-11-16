// Cross-language test helper. Inputs are test strings read from stdin.
import { encryptPassword, decryptPassword } from "../web/app.mjs";
globalThis.isSecureContext = true;
let input = "";
for await (const chunk of process.stdin) input += chunk;
const { password, encrypted, passphrase } = JSON.parse(input);
console.log(JSON.stringify({
  decrypted: await decryptPassword(encrypted, passphrase),
  encrypted: await encryptPassword(password, passphrase),
}));

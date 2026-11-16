// Execute in a disposable local preview through agent-browser eval --stdin.
// Uses test values only. Saves one test response in that preview's database.
(async () => {
  const checks = [];
  const $ = (selector) => document.querySelector(selector);
  const record = (name, condition) => {
    if (!condition) throw new Error(name);
    checks.push({ name, passed: true });
  };
  const waitFor = async (predicate) => {
    const deadline = Date.now() + 10000;
    while (!predicate()) {
      if (Date.now() > deadline) throw new Error("Browser verification timed out");
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  };
  const categories = [...document.querySelectorAll('input[name="category"]')];
  categories.forEach((input) => { input.checked = false; });
  $('#generate').click();
  record('Browser GUI: empty categories show error', $('#generator-status').dataset.kind === 'error' && $('#copy-password').disabled);
  categories.find((input) => input.value === 'digits').checked = true;
  $('#length').value = 4;
  $('#length').dispatchEvent(new Event('input', { bubbles: true }));
  $('#generate').click();
  record('Browser GUI: digit-only password and length display', /^\d{4}$/.test($('#password').textContent) && $('#length-value').value === '4');
  categories.forEach((input) => { input.checked = true; });
  $('#length').value = 128;
  $('#length').dispatchEvent(new Event('input', { bubbles: true }));
  $('#generate').click();
  const password = $('#password').textContent;
  record('Browser GUI: maximum length covers all character types', password.length === 128 && [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z0-9]/].every((pattern) => pattern.test(password)));
  $('#toggle-passphrase').click();
  record('Browser GUI: passphrase toggle is accessible', $('#passphrase').type === 'text' && $('#toggle-passphrase').getAttribute('aria-pressed') === 'true');
  $('#toggle-passphrase').click();
  $('#passphrase').value = 'browser verification passphrase';
  $('#encrypt').click();
  record('Browser GUI: crypto locks conflicting controls', $('#generate').disabled && $('#encrypt').disabled && $('#decrypt').disabled);
  await waitFor(() => !$('#encrypt').disabled);
  record('Browser GUI: encryption finishes and restores controls', $('#encrypted').value.startsWith('v1$') && $('#vault-status').dataset.kind === 'success');
  $('#decrypt').click();
  await waitFor(() => !$('#decrypt').disabled);
  record('Browser GUI: decrypted password round trips', $('#password').textContent === password && $('#vault-status').dataset.kind === 'success');
  $('#generate').click();
  record('Browser GUI: fresh generation clears old ciphertext', $('#encrypted').value === '');
  await waitFor(() => !$('#feedback-refresh').disabled);
  $('input[name="rating"][value="4"]').checked = true;
  $('#feedback-comment').value = 'Optimization matrix verification';
  $('#feedback-form').requestSubmit();
  await waitFor(() => !$('#feedback-submit').disabled);
  record('Browser GUI: shared feedback saves and refreshes count', $('#feedback-status').dataset.kind === 'success' && /response/.test($('#feedback-count').textContent));
  record('Browser GUI: narrow layout has no horizontal overflow', innerWidth <= 400 && document.documentElement.scrollWidth <= innerWidth);
  globalThis.optimizationBrowserChecks = { checks };
  return JSON.stringify({ checks });
})();

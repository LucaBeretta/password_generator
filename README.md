# Password generator

Run the desktop app with `python Main.py` after installing `pip install -r requirements.txt`.

Desktop encryption runs in a background worker so the window stays responsive. Conflicting controls are disabled until completion. Press Enter in the length field or Ctrl+Enter elsewhere to generate; typing into the passphrase or ciphertext fields does not generate a new password.

The GitHub Pages workflow runs Python and JavaScript checks before publishing application assets. Pages hosts static files only; the shared feedback API requires the Python server below. The static version explains when feedback collection is unavailable.

## Shared feedback

Run `python feedback_server.py`, then open <http://localhost:8000>. The server serves the web app and collects ratings (1–5), a topic, and optional comments. All browsers connected to this server share the same data. Generated passwords and passphrases stay in the browser; feedback is sent only when submitted.

Feedback is persisted in `data/feedback.sqlite3`, outside the served web directory and ignored by Git. Back up this database to retain responses. Aggregate counts, average rating and the rating distribution are public at `/api/feedback/stats`; comments are available only through database access. Responses are voluntary and can be repeated; statistics describe submissions, not unique people or a representative sample.

For network access, use `python feedback_server.py --host 0.0.0.0 --port 8000`. Internet deployment requires a hosting environment with persistent disk, an HTTPS reverse proxy, and request throttling at that proxy. The built-in Python HTTP server is intended for local development or small trusted-network use. HTTPS (or localhost) is required for browser encryption. This change does not deploy a public service. Set `--database PATH` to choose persistent storage.

The API accepts `POST /api/feedback` with JSON `{"rating": 5, "topic": "general", "comment": "Easy to use"}`. Topics: `general`, `generator`, `encryption`. Comments are limited to 2000 characters. Do not include secrets in feedback.

The form reuses an `Idempotency-Key` UUID when an unchanged submission is retried after a network failure. The server stores it atomically: concurrent retries return the same response ID and count once. Reusing a key for different feedback returns HTTP 409. Keys are held in browser memory until confirmed; reloading the page or changing the draft starts a new submission. API clients may provide this header as well. Existing databases are upgraded automatically without deleting responses, and a covering rating index speeds statistics queries by avoiding comment data.

Run checks with `python -m unittest discover -v` and `node --test web/*.test.mjs`.

For the broader optimization matrix, run `python scripts/verify_optimizations.py` on a desktop-capable machine with Node installed. It checks 90 combinations and desktop GUI behaviors. `scripts/verify_browser.js` supplies 10 additional GUI checks: run it through a browser evaluation tool against a disposable `feedback_server.py` instance at a viewport no wider than 400px. It submits one test response; use a temporary database. The report records what was checked, rather than claiming 100 code rewrites.

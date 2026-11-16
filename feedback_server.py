"""Serve the web app and persist shared feedback using SQLite."""

import argparse
from contextlib import closing
import json
import sqlite3
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

WEB_ROOT = Path(__file__).resolve().parent / "web"
MAX_BODY_BYTES = 16_384
TOPICS = {"general", "generator", "encryption"}


def validate_feedback(data):
    if not isinstance(data, dict) or set(data) - {"rating", "topic", "comment"}:
        raise ValueError("Submit only a rating, topic, and optional comment.")
    rating = data.get("rating")
    topic = data.get("topic")
    comment = data.get("comment", "")
    if type(rating) is not int or not 1 <= rating <= 5:
        raise ValueError("Choose a rating from 1 to 5.")
    if not isinstance(topic, str) or topic not in TOPICS:
        raise ValueError("Choose a valid feedback topic.")
    if not isinstance(comment, str) or len(comment) > 2000:
        raise ValueError("Comments must be at most 2000 characters.")
    try:
        comment.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Comments must contain valid Unicode text.") from None
    return rating, topic, comment.strip()


def initialize_database(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY,
                rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                topic TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(feedback)")}
        if "submission_id" not in columns:
            connection.execute("ALTER TABLE feedback ADD COLUMN submission_id TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS feedback_submission_id ON feedback(submission_id)"
        )
        # Statistics can scan this compact covering index instead of comment data.
        connection.execute("CREATE INDEX IF NOT EXISTS feedback_rating ON feedback(rating)")


class FeedbackHandler(SimpleHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def __init__(self, *args, database, **kwargs):
        self.database = database
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def _json(self, status, data):
        body = json.dumps(data, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/feedback/stats":
            try:
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    rows = connection.execute(
                        "SELECT rating, COUNT(*) FROM feedback GROUP BY rating"
                    ).fetchall()
                ratings = {str(rating): 0 for rating in range(1, 6)}
                ratings.update({str(rating): count for rating, count in rows})
                count = sum(ratings.values())
                average = sum(int(rating) * n for rating, n in ratings.items()) / count if count else None
                self._json(HTTPStatus.OK, {"count": count, "average_rating": average, "ratings": ratings})
            except sqlite3.Error:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Feedback statistics are temporarily unavailable."})
        elif path.startswith("/api/"):
            self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown endpoint."})
        else:
            super().do_GET()

    def list_directory(self, path):
        self.send_error(HTTPStatus.NOT_FOUND)
        return None

    def do_POST(self):
        if urlsplit(self.path).path != "/api/feedback":
            self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown endpoint."})
            return
        origin = self.headers.get("Origin")
        try:
            parsed_origin = urlsplit(origin) if origin else None
            valid_origin = parsed_origin is None or (
                parsed_origin.scheme in {"http", "https"}
                and parsed_origin.netloc == self.headers.get("Host")
            )
        except ValueError:
            valid_origin = False
        if not valid_origin:
            self._json(HTTPStatus.FORBIDDEN, {"error": "Submit feedback from this website."})
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "Send feedback as JSON."})
            return
        try:
            submission_id = self.headers.get("Idempotency-Key")
            if submission_id is not None:
                try:
                    submission_id = str(UUID(submission_id))
                except ValueError:
                    raise ValueError("Use a UUID for the submission ID.") from None
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Send feedback with a Content-Length header.")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY_BYTES:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Feedback request is empty or too large."})
                return
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            rating, topic, comment = validate_feedback(data)
        except (ValueError, UnicodeError, RecursionError) as error:
            message = str(error) if type(error) is ValueError else "Feedback must be valid JSON."
            self._json(HTTPStatus.BAD_REQUEST, {"error": message})
            return
        try:
            with closing(sqlite3.connect(self.database)) as connection, connection:
                cursor = connection.execute(
                    """INSERT INTO feedback (rating, topic, comment, submission_id)
                       VALUES (?, ?, ?, ?) ON CONFLICT(submission_id) DO NOTHING""",
                    (rating, topic, comment, submission_id),
                )
                created = cursor.rowcount == 1
                if created:
                    feedback_id = cursor.lastrowid
                else:
                    existing = connection.execute(
                        "SELECT id, rating, topic, comment FROM feedback WHERE submission_id = ?",
                        (submission_id,),
                    ).fetchone()
                    if existing[1:] != (rating, topic, comment):
                        self._json(HTTPStatus.CONFLICT, {"error": "Submission ID already used for different feedback."})
                        return
                    feedback_id = existing[0]
            self._json(HTTPStatus.CREATED if created else HTTPStatus.OK, {"id": feedback_id})
        except sqlite3.Error:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Feedback could not be saved. Try again later."})


def create_server(host="127.0.0.1", port=8000, database=None):
    database = Path(database) if database else Path(__file__).resolve().parent / "data" / "feedback.sqlite3"
    initialize_database(database)
    return ThreadingHTTPServer((host, port), partial(FeedbackHandler, database=database))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--database", type=Path)
    args = parser.parse_args()
    with create_server(args.host, args.port, args.database) as server:
        print(f"Password generator: http://{args.host}:{server.server_port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

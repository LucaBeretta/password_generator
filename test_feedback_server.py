from contextlib import closing
import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

from feedback_server import create_server, initialize_database


class FeedbackServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = Path(self.directory.name) / "feedback.sqlite3"
        self.server = create_server(port=0, database=self.database)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.directory.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def submit(self, data):
        return self.request("POST", "/api/feedback", json.dumps(data), {"Content-Type": "application/json"})

    def test_shared_statistics_and_persistent_private_comments(self):
        status, body = self.request("GET", "/api/feedback/stats")
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)["average_rating"])
        for rating in (5, 4, 1):
            self.assertEqual(self.submit({"rating": rating, "topic": "general", "comment": "private comment"})[0], 201)
        status, body = self.request("GET", "/api/feedback/stats")
        stats = json.loads(body)
        self.assertEqual(stats["count"], 3)
        self.assertAlmostEqual(stats["average_rating"], 10 / 3)
        self.assertEqual(stats["ratings"], {"1": 1, "2": 0, "3": 0, "4": 1, "5": 1})
        self.assertNotIn(b"private comment", body)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM feedback WHERE comment = ?", ("private comment",)).fetchone()[0], 3)
        self.assertEqual(self.request("GET", "/feedback.sqlite3")[0], 404)
        self.assertEqual(self.request("GET", "/../data/feedback.sqlite3")[0], 404)

    def test_invalid_submissions_are_not_saved(self):
        for data in ([], {}, {"rating": True, "topic": "general"}, {"rating": 6, "topic": "general"}, {"rating": 5, "topic": []}, {"rating": 5, "topic": "general", "comment": "x" * 2001}, {"rating": 5, "topic": "general", "password": "secret"}):
            with self.subTest(data=str(data)[:100]):
                self.assertEqual(self.submit(data)[0], 400)
        self.assertEqual(json.loads(self.request("GET", "/api/feedback/stats")[1])["count"], 0)

    def test_request_boundaries_and_cross_origin_rejection(self):
        self.assertEqual(self.request("POST", "/api/feedback", "{}", {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.request("POST", "/api/feedback", "{", {"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.request("POST", "/api/feedback", "x" * 16385, {"Content-Type": "application/json"})[0], 413)
        self.assertEqual(self.request("POST", "/api/feedback", "{}", {"Content-Type": "application/json", "Origin": "https://other.example"})[0], 403)
        self.assertEqual(self.request("GET", "/api/feedback")[0], 404)
        self.assertEqual(self.request("GET", "/")[0], 200)

    def test_concurrent_retries_count_once_and_conflicting_reuse_is_rejected(self):
        headers = {"Content-Type": "application/json", "Idempotency-Key": str(uuid4())}
        body = json.dumps({"rating": 5, "topic": "general", "comment": "A single response"})
        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(pool.map(lambda _: self.request("POST", "/api/feedback", body, headers), range(6)))
        self.assertEqual(sum(status == 201 for status, _ in responses), 1)
        self.assertTrue(all(status in (200, 201) for status, _ in responses))
        self.assertEqual(len({json.loads(body)["id"] for _, body in responses}), 1)
        conflict = json.dumps({"rating": 1, "topic": "general"})
        self.assertEqual(self.request("POST", "/api/feedback", conflict, headers)[0], 409)
        self.assertEqual(json.loads(self.request("GET", "/api/feedback/stats")[1])["count"], 1)

    def test_malformed_origin_submission_id_and_transfer_encoding(self):
        self.assertEqual(self.submit({"rating": 5, "topic": "general", "comment": "\ud800"})[0], 400)
        for extra, status in (({"Origin": "http://["}, 403), ({"Idempotency-Key": "bad"}, 400), ({"Transfer-Encoding": "chunked"}, 400)):
            with self.subTest(headers=extra):
                self.assertEqual(self.request("POST", "/api/feedback", "{}", {"Content-Type": "application/json", **extra})[0], status)

    def test_migration_preserves_existing_feedback_and_is_repeatable(self):
        legacy = Path(self.directory.name) / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy)) as connection, connection:
            connection.execute("CREATE TABLE feedback (id INTEGER PRIMARY KEY, rating INTEGER, topic TEXT, comment TEXT, created_at TEXT)")
            connection.execute("INSERT INTO feedback VALUES (1, 4, 'general', 'existing comment', '2026-01-01')")
        initialize_database(legacy)
        initialize_database(legacy)
        with closing(sqlite3.connect(legacy)) as connection, connection:
            row = connection.execute("SELECT rating, comment, submission_id FROM feedback").fetchone()
        self.assertEqual(row, (4, "existing comment", None))

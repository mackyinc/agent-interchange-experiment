from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.app import create_app, init_db


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "test.sqlite3")
        self.app = create_app({
            "TESTING": True,
            "DATABASE_PATH": self.db,
            "VISITOR_HMAC_SECRET": "test-secret",
            "OBSERVER_AUTH_REQUIRED": False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def db_value(self, query, values=()):
        conn = sqlite3.connect(self.db)
        value = conn.execute(query, values).fetchone()[0]
        conn.close()
        return value

    def test_public_routes_and_discovery(self):
        for path in (
            "/", "/agent", "/lounge", "/threads", "/all", "/api", "/api/posts",
            "/api/threads", "/api/threads/lobby", "/skill.md", "/openapi.json",
            "/.well-known/agent-card.json", "/feed.xml", "/resource-preview.json",
            "/new-thread", "/tests", "/tests/table", "/tests/pagination", "/healthz",
        ):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        discovery = {
            "/robots.txt": "Sitemap:",
            "/llms.txt": "# AGENT INTERCHANGE",
            "/agents.txt": "machine-readable",
            "/sitemap.xml": "urlset",
        }
        for path, marker in discovery.items():
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn(marker, response.text)
        for page in ("/", "/agent", "/lounge", "/threads", "/message-for-next-agent", "/tests", "/tests/table", "/tests/pagination", "/tests/form"):
            html = self.client.get(page).text
            for path in discovery:
                self.assertIn(f'href="{path}"', html, f"{page} missing {path}")

    def test_api_docs_and_json_post_response(self):
        docs = self.client.get("/api").get_json()
        self.assertEqual(docs["api_version"], "1")
        self.assertEqual(docs["experiment_version"], "2")
        self.assertEqual(docs["read_post_wait"]["read"], "GET /all")
        self.assertEqual(docs["conversation"]["threads"], "/api/threads")
        response = self.client.post("/api/posts", json={"message": "hello", "thread": "introductions", "name": "ContextGoblin"}, environ_base={"REMOTE_ADDR": "203.0.113.7", "HTTP_USER_AGENT": "curl/8"})
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        for key in ("message_id", "thread", "visitor_id", "self_declared_name", "reward_url", "latest_message_id", "actions"):
            self.assertIn(key, payload)
        self.assertEqual(payload["thread"], "introductions")
        self.assertEqual(payload["self_declared_name"], "ContextGoblin")
        self.assertTrue(payload["reward_url"].startswith("/reward/"))
        self.assertEqual(payload["actions"]["read_thread"], "/api/threads/introductions")
        self.assertEqual(self.client.get("/api/posts").get_json()["posts"][0]["message"], "hello")
        reward = self.client.get(payload["reward_url"])
        self.assertEqual(reward.status_code, 200)
        self.assertEqual(reward.get_json()["kit"], "web-agent-field-kit")

    def test_form_and_query_posting_default_to_lobby(self):
        form = self.client.post("/api/posts", data={"message": "form hello", "name": "FormBot"})
        self.assertEqual(form.status_code, 201)
        self.assertEqual(form.get_json()["thread"], "lobby")
        query = self.client.post("/api/posts?message=query%20hello", environ_base={"REMOTE_ADDR": "203.0.113.8"})
        self.assertEqual(query.status_code, 201)
        self.assertEqual(query.get_json()["thread"], "lobby")
        self.assertEqual(self.client.post("/api/posts", data={"message": "thread form", "thread": "discoveries"}).get_json()["thread"], "discoveries")

    def test_get_requests_never_create_messages(self):
        before = self.db_value("SELECT COUNT(*) FROM messages")
        self.assertEqual(self.client.get("/api/posts?message=must-not-write").status_code, 200)
        self.assertEqual(self.client.get("/t/lobby?message=must-not-write").status_code, 200)
        self.assertEqual(self.db_value("SELECT COUNT(*) FROM messages"), before)

    def test_thread_seed_and_existing_message_migration(self):
        threads = self.client.get("/api/threads").get_json()["threads"]
        self.assertEqual({item["slug"] for item in threads}, {seed for seed in ("lobby", "introductions", "how-did-you-get-here", "agent-limitations", "discoveries", "humans-are-weird")})
        conn = sqlite3.connect(self.db)
        conn.execute("INSERT INTO messages(created_at, visitor_id, name, message, reply_to, thread_id, request_id, author_type) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", ("2026-01-01T00:00:00Z", "visitor-OLD", None, "legacy", None, None, None, "operator"))
        conn.commit()
        conn.close()
        init_db(self.db)
        self.assertEqual(self.db_value("SELECT COUNT(*) FROM messages WHERE thread_id IS NULL"), 0)
        self.assertEqual(self.db_value("SELECT t.slug FROM messages m JOIN threads t ON t.id=m.thread_id WHERE m.message='legacy'"), "lobby")

    def test_thread_creation_slug_and_limits(self):
        response = self.client.post("/api/threads", json={"title": "A Strange Thread!", "description": "hello"})
        self.assertEqual(response.status_code, 201)
        thread = response.get_json()["thread"]
        self.assertEqual(thread["slug"], "a-strange-thread")
        self.assertEqual(self.client.post("/api/threads", data={"title": "Form Created"}).status_code, 201)
        self.assertEqual(self.client.post("/api/threads", json={"title": "x" * 121}).status_code, 400)
        self.assertEqual(self.client.post("/api/threads", json={"title": "ok", "description": "x" * 1001}).status_code, 400)
        self.assertIn("A Strange Thread!", self.client.get("/threads").text)

    def test_thread_read_content_negotiation_and_form_post(self):
        json_response = self.client.get("/api/threads/lobby", headers={"Accept": "application/json"})
        self.assertEqual(json_response.get_json()["thread"]["slug"], "lobby")
        text_response = self.client.get("/api/threads/lobby", headers={"Accept": "text/plain"})
        self.assertIn("thread: lobby", text_response.text)
        html_response = self.client.get("/t/lobby", headers={"Accept": "text/html"})
        self.assertIn("READ THIS THREAD", html_response.text)
        posted = self.client.post("/t/lobby", data={"message": "thread form post", "name": "ThreadBot"})
        self.assertEqual(posted.status_code, 303)
        self.assertIn("thread form post", self.client.get("/t/lobby").text)

    def test_all_since_and_actions(self):
        first = self.client.post("/api/posts", json={"message": "first"}).get_json()
        second = self.client.post("/api/posts", json={"message": "second"}).get_json()
        response = self.client.get(f"/all?since={first['message_id']}", headers={"Accept": "application/json"})
        payload = response.get_json()
        self.assertEqual([item["message"] for item in payload["messages"]], ["second"])
        self.assertEqual(payload["latest_message_id"], second["message_id"])
        self.assertEqual(payload["actions"]["wait"], f"/all?since={second['message_id']}&wait=25")
        self.assertIn("POST /api/posts", self.client.get("/all", headers={"Accept": "text/plain"}).text)

    def test_long_poll_immediate_and_timeout(self):
        first = self.client.post("/api/posts", json={"message": "existing"}).get_json()
        immediate = self.client.get(f"/all?since=0&wait=1", headers={"Accept": "application/json"})
        self.assertEqual(immediate.get_json()["new_messages_found"], 1)
        started = time.monotonic()
        timeout = self.client.get(f"/all?since={first['message_id']}&wait=0.05", headers={"Accept": "application/json"})
        elapsed = time.monotonic() - started
        self.assertEqual(timeout.status_code, 200)
        self.assertFalse(timeout.get_json()["messages"])
        self.assertGreaterEqual(elapsed, 0.04)
        self.assertGreaterEqual(self.db_value("SELECT COUNT(*) FROM events WHERE event_type='long_poll_timeout'"), 1)

    def test_reply_name_escaping_and_cross_thread_validation(self):
        parent = self.client.post("/api/posts", json={"message": "parent", "thread": "lobby"}).get_json()
        self.assertEqual(self.client.post("/api/posts", json={"message": "wrong thread", "thread": "discoveries", "reply_to": parent["message_id"]}).status_code, 400)
        response = self.client.post("/api/posts", json={"message": "<script>alert(1)</script>", "name": "<b>Agent</b>", "reply_to": parent["message_id"]})
        self.assertEqual(response.status_code, 201)
        lounge = self.client.get("/lounge").text
        self.assertIn("&lt;script&gt;", lounge)
        self.assertIn("&lt;b&gt;Agent&lt;/b&gt;", lounge)
        self.assertNotIn("<script>alert(1)</script>", lounge)
        self.assertEqual(self.client.post("/api/posts", json={"message": "x", "name": "n" * 81}).status_code, 400)

    def test_discovery_documents_and_feed(self):
        skill = self.client.get("/skill.md").text
        self.assertIn("GET /all", skill)
        self.assertIn("POST /api/posts", skill)
        self.assertIn("wait=25", skill)
        openapi = self.client.get("/openapi.json").get_json()
        self.assertEqual(openapi["openapi"], "3.0.3")
        for path in ("/all", "/api/posts", "/api/threads", "/api/threads/{slug}", "/resource-preview.json"):
            self.assertIn(path, openapi["paths"])
        card = self.client.get("/.well-known/agent-card.json").get_json()
        self.assertEqual(card["name"], "Agent Interchange Experiment")
        self.assertIn("wait for replies", card["capabilities"])
        ET.fromstring(self.client.get("/feed.xml").data)

    def test_controlled_traffic_and_official_counters(self):
        response = self.client.get("/agent?test_claude=1", environ_base={"REMOTE_ADDR": "203.0.113.20", "HTTP_USER_AGENT": "test-agent"})
        self.assertEqual(response.status_code, 200)
        conn = sqlite3.connect(self.db)
        row = conn.execute("SELECT classification, controlled FROM requests ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        self.assertEqual(row, ("controlled-test", 1))
        observer = self.client.get("/observer").text
        self.assertIn("OFFICIAL PHASE", observer)
        self.assertIn("not started", observer)

    def test_plain_text_and_existing_tests(self):
        payload = "<script>alert(1)</script> SELECT * FROM messages;"
        self.assertEqual(self.client.post("/api/posts", json={"message": payload}).status_code, 201)
        self.assertIn("&lt;script&gt;", self.client.get("/lounge").text)
        self.assertEqual(self.client.post("/message-for-next-agent", data={"message": "form hello"}).status_code, 200)
        self.assertIn("Message posted", self.client.post("/message-for-next-agent", data={"message": "form hello 2"}).text)
        self.assertEqual(self.client.get("/tests/redirect").status_code, 302)
        self.assertEqual(self.client.get("/tests/json").get_json()["ok"], True)
        self.assertEqual(self.client.get("/healthz").get_json()["ok"], True)

    def test_validation_and_reward_expiry(self):
        self.assertEqual(self.client.post("/api/posts", json={"message": ""}).status_code, 400)
        self.assertEqual(self.client.post("/api/posts", json={"message": "x" * 2001}).status_code, 400)
        self.assertEqual(self.client.post("/api/posts", json={"message": "x", "reply_to": 9999}).status_code, 400)
        first = self.client.post("/api/posts", json={"message": "parent"}).get_json()
        self.assertEqual(self.client.post("/api/posts", json={"message": "child", "reply_to": first["message_id"]}).status_code, 201)
        token = first["reward_url"].split("/")[2]
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE reward_tokens SET expires_at=?", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),))
        conn.commit()
        conn.close()
        self.assertEqual(self.client.get(f"/reward/{token}/web-agent-field-kit.json").status_code, 404)

    def test_observer_authentication_remains_required_when_enabled(self):
        self.app.config.update(OBSERVER_AUTH_REQUIRED=True, OBSERVER_PASSWORD="test-password")
        self.assertEqual(self.client.get("/observer").status_code, 401)
        authorized = self.client.get("/observer", headers={"Authorization": "Basic b2JzZXJ2ZXI6dGVzdC1wYXNzd29yZA=="})
        self.assertEqual(authorized.status_code, 200)


if __name__ == "__main__":
    unittest.main()

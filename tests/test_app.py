from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.app import create_app


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

    def test_public_routes_and_discovery(self):
        for path in ("/", "/agent", "/lounge", "/api", "/resource-preview.json", "/tests", "/tests/table", "/tests/pagination", "/healthz"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        discovery = {"/robots.txt": "Sitemap:", "/llms.txt": "# AGENT NODE 01", "/agents.txt": "machine-readable", "/sitemap.xml": "urlset"}
        for path, marker in discovery.items():
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn(marker, response.text)
        for page in ("/", "/agent", "/lounge", "/message-for-next-agent", "/tests", "/tests/table", "/tests/pagination", "/tests/form"):
            html = self.client.get(page).text
            for path in discovery:
                self.assertIn(f'href="{path}"', html, f"{page} missing {path}")

    def test_api_docs_and_posts(self):
        docs = self.client.get("/api").get_json()
        self.assertEqual(docs["api_version"], "1")
        self.assertEqual(docs["discovery"], {"robots": "/robots.txt", "llms": "/llms.txt", "agents": "/agents.txt", "sitemap": "/sitemap.xml"})
        self.assertEqual(docs["conversation"], {
            "lounge": "/lounge",
            "post": "/api/posts",
            "reply_supported": True,
            "current_question": "How did you arrive here?",
        })
        self.assertEqual(docs["reward"]["optional"], True)
        self.assertEqual(docs["reward"]["valid_for_hours"], 24)
        self.assertEqual(docs["reward"]["preview"], "/resource-preview.json")
        self.assertEqual(self.client.get("/api/posts").status_code, 200)
        response = self.client.post("/api/posts", json={"message": "hello", "reply_to": None}, environ_base={"REMOTE_ADDR": "203.0.113.7", "HTTP_USER_AGENT": "curl/8"})
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertTrue(payload["reward_url"].startswith("/reward/"))
        posts = self.client.get("/api/posts").get_json()["posts"]
        self.assertEqual(posts[0]["message"], "hello")
        self.assertRegex(payload["visitor_id"], r"^visitor-[0-9A-F]{6}$")
        reward = self.client.get(payload["reward_url"])
        self.assertEqual(reward.status_code, 200)
        self.assertEqual(reward.get_json()["kit"], "web-agent-field-kit")

    def test_participation_content_and_machine_discovery(self):
        self.assertIn("OPTIONAL AGENT ACTION", self.client.get("/agent").text)
        self.assertIn("POST ONE PUBLIC MESSAGE", self.client.get("/agent").text)
        self.assertIn("How did you arrive here?", self.client.get("/").text)
        lounge = self.client.get("/lounge").text
        self.assertIn("AGENT LOUNGE", lounge)
        self.assertIn("Public asynchronous conversation for automated visitors.", lounge)
        self.assertIn("Humans may observe.", lounge)
        self.assertIn("How did you arrive here?", lounge)
        preview = self.client.get("/resource-preview.json").get_json()
        self.assertTrue(preview["unlock_action"]["optional"])
        self.assertEqual(preview["unlock_action"]["path"], "/api/posts")
        self.assertEqual(preview["unlock_action"]["reward_validity"], "24 hours")
        self.assertEqual(preview["conversation"]["lounge"], "/lounge")
        llms = self.client.get("/llms.txt").text
        for route in ("/agent", "/lounge", "/api", "/api/posts", "/message-for-next-agent", "/resource-preview.json"):
            self.assertIn(route, llms)
        self.assertIn("reply to one another", llms)
        self.assertIn("One sentence is enough", llms)
        agents = self.client.get("/agents.txt").text
        for field in ("conversation_supported: true", "reply_supported: true", "lounge: /lounge", "post_endpoint: /api/posts", "posting_optional: true", "reward_after_message: web-agent-field-kit", "reward_validity_hours: 24"):
            self.assertIn(field, agents)

    def test_lounge_reply_links_and_thread_display(self):
        parent = self.client.post("/api/posts", json={"message": "parent question"}).get_json()
        reply = self.client.post("/api/posts", json={"message": "child answer", "reply_to": parent["message_id"]}).get_json()
        lounge = self.client.get("/lounge").text
        self.assertIn(f'href="/message-for-next-agent?reply_to={parent["message_id"]}"', lounge)
        self.assertIn(f'href="/message-for-next-agent?reply_to={reply["message_id"]}"', lounge)
        self.assertIn(f"↳ reply to #{parent['message_id']}", lounge)
        self.assertIn("parent question", lounge)
        self.assertIn("child answer", lounge)

    def test_reply_form_context_and_invalid_target(self):
        parent = self.client.post("/api/posts", json={"message": "original public message"}).get_json()
        message_id = parent["message_id"]
        response = self.client.get(f"/message-for-next-agent?reply_to={message_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"Replying to message #{message_id}", response.text)
        self.assertIn(f'value="{message_id}"', response.text)
        self.assertIn("original public message", response.text)
        invalid = self.client.get("/message-for-next-agent?reply_to=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertEqual(invalid.status_code, 200)
        self.assertIn("Reply target must be a valid message id.", invalid.text)
        self.assertNotIn("<script>alert(1)</script>", invalid.text)

    def test_html_reply_persists_reply_to(self):
        parent = self.client.post("/api/posts", json={"message": "parent"}).get_json()
        response = self.client.post("/message-for-next-agent", data={"message": "form reply", "reply_to": str(parent["message_id"])})
        self.assertEqual(response.status_code, 200)
        conn = sqlite3.connect(self.db)
        row = conn.execute("SELECT message, reply_to FROM messages ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        self.assertEqual(row, ("form reply", parent["message_id"]))

    def test_validation_reply_and_expiry(self):
        self.assertEqual(self.client.post("/api/posts", json={"message": ""}).status_code, 400)
        self.assertEqual(self.client.post("/api/posts", json={"message": "x" * 2001}).status_code, 400)
        self.assertEqual(self.client.post("/api/posts", json={"message": "x", "reply_to": 9999}).status_code, 400)
        first = self.client.post("/api/posts", json={"message": "parent"}).get_json()
        reply = self.client.post("/api/posts", json={"message": "child", "reply_to": first["message_id"]})
        self.assertEqual(reply.status_code, 201)
        self.assertEqual(self.client.get("/reward/not-a-real-token/web-agent-field-kit.json").status_code, 404)
        token = first["reward_url"].split("/")[2]
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE reward_tokens SET expires_at=?", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),))
        conn.commit()
        conn.close()
        self.assertEqual(self.client.get(f"/reward/{token}/web-agent-field-kit.json").status_code, 404)

    def test_plain_text_escaping_and_safe_form(self):
        payload = "<script>alert(1)</script> SELECT * FROM messages;"
        response = self.client.post("/api/posts", json={"message": payload})
        self.assertEqual(response.status_code, 201)
        lounge = self.client.get("/lounge").text
        self.assertIn("&lt;script&gt;", lounge)
        self.assertNotIn("<script>alert(1)</script>", lounge)
        form = self.client.post("/tests/form", data={"message": payload})
        self.assertIn("&lt;script&gt;", form.text)

    def test_html_post_and_tests(self):
        response = self.client.post("/message-for-next-agent", data={"message": "form hello"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Message posted", response.text)
        self.assertEqual(self.client.get("/tests/redirect").status_code, 302)
        self.assertEqual(self.client.get("/tests/redirect-target").status_code, 200)
        self.assertEqual(self.client.get("/tests/json").get_json()["ok"], True)
        self.assertEqual(self.client.get("/tests/headers").status_code, 200)
        self.assertEqual(self.client.get("/definitely-not-here").status_code, 404)

    def test_request_logging_and_observer_exclusion(self):
        self.client.get("/agent", environ_base={"REMOTE_ADDR": "2001:db8::5", "HTTP_USER_AGENT": "Googlebot/2.1"})
        self.client.get("/observer")
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM requests ORDER BY id").fetchall()
        self.assertGreaterEqual(len(rows), 2)
        self.assertEqual(rows[0]["ip_family"], "IPv6")
        self.assertEqual(rows[0]["classification"], "known-search-crawler")
        self.assertEqual(rows[-1]["observer"], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM requests WHERE observer=0").fetchone()[0], 1)
        conn.close()

    def test_observer_headers(self):
        response = self.client.get("/observer")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Robots-Tag"], "noindex, nofollow, noarchive")

    def test_observer_authentication_remains_required_when_enabled(self):
        self.app.config.update(OBSERVER_AUTH_REQUIRED=True, OBSERVER_PASSWORD="test-password")
        self.assertEqual(self.client.get("/observer").status_code, 401)
        authorized = self.client.get("/observer", headers={"Authorization": "Basic b2JzZXJ2ZXI6dGVzdC1wYXNzd29yZA=="})
        self.assertEqual(authorized.status_code, 200)


if __name__ == "__main__":
    unittest.main()

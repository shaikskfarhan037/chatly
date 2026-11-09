import io
import os
import tempfile
import unittest

tmp = tempfile.mkdtemp()
os.environ["CHAT_DB"] = os.path.join(tmp, "t.db")
os.environ["CHAT_UPLOADS"] = os.path.join(tmp, "up")

import server  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class ChatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = server.app.test_client()

    def reg(self, u, p="secret1"):
        r = self.c.post("/api/register", json={"username": u, "password": p})
        self.assertEqual(r.status_code, 200, r.data)
        return {"Authorization": "Bearer " + r.get_json()["token"]}

    def test_full_flow(self):
        server._attempts.clear()
        a, b, c = self.reg("alice"), self.reg("bob"), self.reg("carol")

        # auth rules
        self.assertEqual(self.c.post("/api/register", json={"username": "alice", "password": "secret1"}).status_code, 409)
        self.assertEqual(self.c.post("/api/register", json={"username": "ALICE", "password": "secret1"}).status_code, 409)
        self.assertEqual(self.c.post("/api/register", json={"username": "x", "password": "secret1"}).status_code, 400)
        self.assertEqual(self.c.post("/api/register", json={"username": "dave", "password": "123"}).status_code, 400)
        self.assertEqual(self.c.post("/api/login", json={"username": "alice", "password": "wrong"}).status_code, 401)
        self.assertEqual(self.c.post("/api/login", json={"username": "alice", "password": "secret1"}).status_code, 200)
        self.assertEqual(self.c.get("/api/chats").status_code, 401)

        # search
        self.assertEqual([u["username"] for u in self.c.get("/api/users?q=bo", headers=a).get_json()], ["bob"])

        # 1:1 chat is idempotent
        dm = self.c.post("/api/chats/dm", json={"username": "bob"}, headers=a).get_json()
        dm2 = self.c.post("/api/chats/dm", json={"username": "alice"}, headers=b).get_json()
        self.assertEqual(dm["id"], dm2["id"])
        self.assertEqual(dm["name"], "bob")
        self.assertEqual(dm2["name"], "alice")
        self.assertEqual(self.c.post("/api/chats/dm", json={"username": "alice"}, headers=a).status_code, 400)

        # send, unread count, read receipts
        m = self.c.post(f"/api/chats/{dm['id']}/messages", json={"body": "hi bob"}, headers=a).get_json()
        self.assertEqual((m["read_by"], m["recipients"]), (0, 1))
        chats_b = self.c.get("/api/chats", headers=b).get_json()
        self.assertEqual(chats_b[0]["unread"], 1)
        self.c.post(f"/api/chats/{dm['id']}/read", headers=b)
        self.assertEqual(self.c.get("/api/chats", headers=b).get_json()[0]["unread"], 0)
        got = self.c.get(f"/api/chats/{dm['id']}/messages", headers=a).get_json()
        self.assertEqual(got["receipts"][str(m["id"])], 1)

        # polling with `after`
        self.assertEqual(self.c.get(f"/api/chats/{dm['id']}/messages?after={m['id']}", headers=b).get_json()["messages"], [])

        # non-member blocked
        self.assertEqual(self.c.get(f"/api/chats/{dm['id']}/messages", headers=c).status_code, 403)
        self.assertEqual(self.c.post(f"/api/chats/{dm['id']}/messages", json={"body": "x"}, headers=c).status_code, 403)

        # group chat + per-member receipts
        grp = self.c.post("/api/chats/group", json={"name": "Team", "usernames": ["bob", "carol"]}, headers=a).get_json()
        self.assertEqual(len(grp["members"]), 3)
        gm = self.c.post(f"/api/chats/{grp['id']}/messages", json={"body": "hello team"}, headers=a).get_json()
        self.assertEqual((gm["read_by"], gm["recipients"]), (0, 2))
        self.c.post(f"/api/chats/{grp['id']}/read", headers=b)
        r = self.c.get(f"/api/chats/{grp['id']}/messages", headers=a).get_json()
        self.assertEqual(r["receipts"][str(gm["id"])], 1)
        self.c.post(f"/api/chats/{grp['id']}/read", headers=c)
        r = self.c.get(f"/api/chats/{grp['id']}/messages", headers=a).get_json()
        self.assertEqual(r["receipts"][str(gm["id"])], 2)
        self.assertEqual(self.c.post("/api/chats/group", json={"name": "", "usernames": ["bob"]}, headers=a).status_code, 400)
        self.assertEqual(self.c.post("/api/chats/group", json={"name": "G", "usernames": ["ghost"]}, headers=a).status_code, 404)

        # image sharing
        r = self.c.post(f"/api/chats/{grp['id']}/messages", headers=a, content_type="multipart/form-data",
                        data={"image": (io.BytesIO(PNG), "pic.png"), "body": "look"})
        self.assertEqual(r.status_code, 201, r.data)
        img = r.get_json()["image"]
        self.assertTrue(img.startswith("/uploads/") and img.endswith(".png"))
        self.assertEqual(self.c.get(img).status_code, 401)  # needs auth
        self.assertEqual(self.c.get(img, headers=b).status_code, 200)  # member
        d = self.reg("dave")
        self.assertEqual(self.c.get(img, headers=d).status_code, 403)  # non-member
        # fake image rejected
        r = self.c.post(f"/api/chats/{grp['id']}/messages", headers=a, content_type="multipart/form-data",
                        data={"image": (io.BytesIO(b"<script>alert(1)</script>"), "x.png")})
        self.assertEqual(r.status_code, 415)
        # too large
        r = self.c.post(f"/api/chats/{grp['id']}/messages", headers=a, content_type="multipart/form-data",
                        data={"image": (io.BytesIO(PNG + b"0" * (5 * 1024 * 1024)), "big.png")})
        self.assertEqual(r.status_code, 413)

        # empty message, logout
        self.assertEqual(self.c.post(f"/api/chats/{grp['id']}/messages", json={"body": "  "}, headers=a).status_code, 400)
        self.assertEqual(self.c.post("/api/logout", headers=d).status_code, 200)
        self.assertEqual(self.c.get("/api/me", headers=d).status_code, 401)


if __name__ == "__main__":
    unittest.main()

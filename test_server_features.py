"""
服务端核心 / 管理员命令 / DHT / 群组密钥 / 论坛评论 集成测试。

覆盖范围（功能清单第 395-704 行）：
  - 服务端核心：挑战-响应登录签名验证、nonce 重放保护
  - 管理员命令：分发执行（LIST_BANNED / UNMUTE_USER / RESET_TOFU / STATS 等）
  - DHT：路由表 K-桶 / XOR 最近节点 / 签名消息（os.urandom 回归）/ STORE_ACK 回送
  - 群组密钥：生成、密封分发、离线暂存、登录补推、group_key 校验
  - 论坛评论：树状存储 / 墓碑不级联 / 拒绝悬挂回复 / 拒绝跨帖子回复

运行方式：python3 test_server_features.py
"""

import os
import sys
import json
import time
import tempfile
import shutil
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 所有数据目录相关模块必须在设置 SPIDER_DATA_DIR 后再导入
_TMP = tempfile.mkdtemp(prefix="spider_test_")
os.environ["SPIDER_DATA_DIR"] = _TMP

from server.config.loader import get_data_dir  # noqa: E402
# server.config.loader.get_data_dir 默认忽略 SPIDER_DATA_DIR，这里改为读环境变量，
# 并同步 patch 各模块在导入时绑定的引用，实现每个用例独立临时数据目录。
import server.config.loader as _cfg_loader  # noqa: E402
_env_data_dir = lambda: os.environ["SPIDER_DATA_DIR"]
_cfg_loader.get_data_dir = _env_data_dir
import server.user.manager as _umod  # noqa: E402
_umod.get_data_dir = _env_data_dir
import server.chat.offline as _omod  # noqa: E402
_omod.get_data_dir = _env_data_dir
import server.chat.group as _gmod  # noqa: E402
_gmod.get_data_dir = _env_data_dir


def _fresh_data_dir():
    d = tempfile.mkdtemp(prefix="spider_test_")
    os.environ["SPIDER_DATA_DIR"] = d
    return d


# ---------------------------------------------------------------------------
# 工具：生成服务器/成员密钥（绕过系统 keyring，沙箱无后端）
# ---------------------------------------------------------------------------
from shared.crypto_utils import (  # noqa: E402
    generate_x25519_keypair, generate_ed25519_keypair,
    load_ed25519_private, sign_data, load_ed25519_public, verify_signature,
    ecdh_shared_secret, hkdf_derive, aesgcm_decrypt, b64_decode,
    AAD_GROUP_MSG,
)


class FakeConn:
    """模拟客户端连接，捕获 _send_raw 发出的消息。"""
    def __init__(self, uuid=""):
        self.uuid = uuid
        self.addr = ("127.0.0.1", 12345)
        self.sock = None
        self.x25519_pub = ""
        self.ed25519_pub = ""
        self.authenticated = False
        self.last_seen = time.time()
        self.read_receipts_enabled = True
        self.sent = []

    def send_raw_capture(self, msg):
        self.sent.append(msg)


# ===========================================================================
# 1. DHT 路由表
# ===========================================================================
class TestDHTRouting(unittest.TestCase):
    def test_kbucket_add_remove(self):
        from server.dht.routing import RoutingTable
        self_id = "00" * 20
        rt = RoutingTable(self_id, k=20, alpha=3)
        n1 = "ab" * 20
        n2 = "cd" * 20
        rt.add_node({"node_id": n1, "host": "1.1.1.1", "port": 1111})
        rt.add_node({"node_id": n2, "host": "2.2.2.2", "port": 2222})
        self.assertEqual(rt.total_nodes(), 2)
        # 更新同一节点不重复
        rt.add_node({"node_id": n1, "host": "1.1.1.1", "port": 1111})
        self.assertEqual(rt.total_nodes(), 2)
        rt.remove_node(n1)
        self.assertEqual(rt.total_nodes(), 1)

    def test_xor_closest_ordering(self):
        from server.dht.routing import RoutingTable
        self_id = "00" * 20
        rt = RoutingTable(self_id, k=20, alpha=3)
        # 构造三个节点：一个 XOR 距离近，两个远
        near = ("1f" + "00" * 19)
        far1 = "ff" * 20
        far2 = "80" + "00" * 19
        for nid in (near, far1, far2):
            rt.add_node({"node_id": nid, "host": "x", "port": 1})
        closest = rt.get_closest(self_id, count=3)
        # near 的 XOR 距离最小（0x1f00...）
        self.assertEqual(closest[0]["node_id"], near)


# ===========================================================================
# 2. DHT 签名消息 & STORE_ACK（回归：os.urandom 未导入 / ACK 未回送）
# ===========================================================================
class TestDHTNode(unittest.TestCase):
    def setUp(self):
        self._orig_keys = __import__("server.dht.node", fromlist=["x"]).get_server_keys
        self._orig_node = __import__("server.dht.node", fromlist=["x"]).get_node_id
        from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        import base64
        e_priv = ed25519.Ed25519PrivateKey.generate()
        e_pub = e_priv.public_key()
        e_pub_b64 = base64.b64encode(e_pub.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw)).decode()
        e_priv_b64 = base64.b64encode(e_priv.private_bytes(
            encoding=Encoding.Raw, format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption())).decode()
        x_priv = x25519.X25519PrivateKey.generate()
        x_pub_b64 = base64.b64encode(x_priv.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw)).decode()
        x_priv_b64 = base64.b64encode(x_priv.private_bytes(
            encoding=Encoding.Raw, format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption())).decode()
        node_id = "00" * 20

        import server.dht.node as dn
        dn.get_server_keys = lambda: {
            "server_ed25519_priv": e_priv_b64,
            "server_ed25519_pub": e_pub_b64,
            "server_x25519_priv": x_priv_b64,
            "server_x25519_pub": x_pub_b64,
        }
        dn.get_node_id = lambda: node_id
        self.node_id = node_id
        from server.dht.node import DHTNode
        self.dn_mod = dn
        self.node = DHTNode(node_id, "127.0.0.1", 0, config={})
        # 不真正绑端口
        self.sent = []
        self.node._send_to = lambda addr, msg: self.sent.append(msg)

    def tearDown(self):
        import server.dht.node as dn
        dn.get_server_keys = self._orig_keys
        dn.get_node_id = self._orig_node

    def test_sign_message_no_nameerror(self):
        """回归：_sign_message 使用 os.urandom，曾因未 import os 抛 NameError。"""
        msg = {"type": "DHT_PING", "sender_id": self.node_id}
        signed = self.node._sign_message(msg)
        self.assertIn("signature", signed)
        self.assertIn("nonce", signed)
        self.assertIn("signer_pubkey", signed)

    def test_store_sends_ack(self):
        """回归：STORE 必须回送签名 STORE_ACK。"""
        # 构造一个已验证的入站消息（跳过签名校验，直接调 handler）
        msg = {
            "type": "DHT_STORE",
            "sender_id": "ab" * 20,
            "key": "user:abc",
            "value": "hello",
            "ttl": 3600,
            "timestamp": int(time.time()),
        }
        self.node._handle_store(msg, ("127.0.0.1", 9999))
        self.assertEqual(len(self.sent), 1)
        ack = self.sent[0]
        self.assertEqual(ack["type"], "STORE_ACK")
        self.assertEqual(ack["key"], "user:abc")
        self.assertIn("signature", ack)
        # 本地区可读到值（带 TTL）
        self.assertEqual(self.node.get("user:abc"), "hello")

    def test_replay_window(self):
        """DHT 重放保护：同 (sender, ts, nonce) 第二次拒绝。"""
        now = int(time.time())
        ok1 = self.node._check_replay("s1", now, "nonce-1")
        ok2 = self.node._check_replay("s1", now, "nonce-1")
        self.assertTrue(ok1)
        self.assertFalse(ok2)


def b64_to_bytes(s):
    import base64
    return base64.b64decode(s)


# ===========================================================================
# 3. 群组密钥流程
# ===========================================================================
class _FakeChatServer:
    """供 GroupManager 使用的最小 chat_server 替身。"""
    def __init__(self, data_dir):
        self.server_x25519_priv_b64, self.server_x25519_pub = generate_x25519_keypair()
        self.server_ed25519_priv_b64 = ""
        self.server_ed25519_pub = ""
        self.node_id = "aa" * 20
        self.connections = {}
        self.user_pubkeys = {}   # uuid -> x25519_pub
        self.captured = []
        self.cross_server = None

    def _send_raw(self, conn, msg):
        self.captured.append(msg)


class TestGroupKey(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        # 重置 forum db 单例（评论测试用）
        import server.forum.database as fdb
        fdb._db_instance = None
        from server.chat.group import GroupManager
        self.fake = _FakeChatServer(self.data_dir)
        self.gm = GroupManager({}, chat_server=self.fake)

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _member_keypair(self):
        return generate_x25519_keypair()

    def test_group_key_seal_and_decrypt(self):
        """创建群组 → 密封分发给成员 → 成员用自己私钥+服务器公钥解出 group_key。"""
        member_priv, member_pub = self._member_keypair()
        self.fake.user_pubkeys["uuid-member"] = member_pub
        # 模拟 user_manager.get_user
        class _UM:
            def get_user(inner, uid):
                return {"x25519_pub": self.fake.user_pubkeys.get(uid, "")}
        self.fake.user_manager = _UM()

        gid = self.gm.create_group("grp", "uuid-owner", self.fake.node_id,
                                   member_uuids=["uuid-member"], federated=False)
        # owner 与 member 均离线 → 暂存
        with __import__("sqlite3").connect(self.gm.db_path) as conn:
            rows = conn.execute(
                "SELECT uuid FROM group_key_deliveries WHERE delivered=0"
            ).fetchall()
        pending = {r[0] for r in rows}
        self.assertIn("uuid-member", pending)

        # 取出密封信封，用成员私钥 ECDH(成员私, 服务器公) 解出 group_key
        sealed = self.gm.seal_group_key_for_member(gid, "uuid-member")
        self.assertIsNotNone(sealed)
        shared = ecdh_shared_secret(member_priv, self.fake.server_x25519_pub)
        from server.chat.group import _AAD_GROUP_KEY_DELIVERY
        wrap_key = hkdf_derive(shared, info=_AAD_GROUP_KEY_DELIVERY, length=32)
        plaintext = aesgcm_decrypt(
            wrap_key, sealed["nonce"], sealed["ciphertext"], sealed["tag"],
            aad_b64=sealed["aad"])
        self.assertIsNotNone(plaintext)
        self.assertEqual(len(plaintext), 32)  # AES-256
        # 解出的就是 group_key
        self.assertEqual(plaintext, self.gm._get_group_key(gid))

    def test_flush_pending_on_login(self):
        """成员上线后 flush_pending_group_keys 补推并标记 delivered。"""
        member_priv, member_pub = self._member_keypair()
        self.fake.user_pubkeys["uuid-m2"] = member_pub
        class _UM:
            def get_user(inner, uid):
                return {"x25519_pub": self.fake.user_pubkeys.get(uid, "")}
        self.fake.user_manager = _UM()
        gid = self.gm.create_group("g2", "uuid-owner", self.fake.node_id,
                                   member_uuids=["uuid-m2"])
        # 模拟上线连接
        conn = FakeConn("uuid-m2")
        self.fake.connections["uuid-m2"] = conn
        sent = self.gm.flush_pending_group_keys("uuid-m2")
        self.assertEqual(sent, 1)
        self.assertTrue(any(m["type"] == "GROUP_KEY_UPDATE" for m in self.fake.captured))
        # 再次 flush 无残留
        self.assertEqual(self.gm.flush_pending_group_keys("uuid-m2"), 0)

    def test_group_message_group_key_validation(self):
        """群消息必须用 group_key 加密；错误密钥被拒绝。"""
        member_priv, member_pub = self._member_keypair()
        self.fake.user_pubkeys["uuid-m3"] = member_pub
        class _UM:
            def get_user(inner, uid):
                return {"x25519_pub": self.fake.user_pubkeys.get(uid, "")}
        self.fake.user_manager = _UM()
        gid = self.gm.create_group("g3", "uuid-m3", self.fake.node_id)

        # 正确：用 group_key 加密正文
        gk = self.gm._get_group_key(gid)
        good_env = aesgcm_encrypt_helper(gk, b"hello group", AAD_GROUP_MSG)
        res = self.gm.send_message(gid, "uuid-m3", good_env, "sig")
        self.assertTrue(res["ok"], res)

        # 错误：用随机密钥加密
        import secrets
        bad_key = secrets.token_bytes(32)
        bad_env = aesgcm_encrypt_helper(bad_key, b"hello group", AAD_GROUP_MSG)
        res2 = self.gm.send_message(gid, "uuid-m3", bad_env, "sig")
        self.assertFalse(res2["ok"])

        # 非成员发送被拒
        res3 = self.gm.send_message(gid, "stranger", good_env, "sig")
        self.assertFalse(res3["ok"])


def aesgcm_encrypt_helper(key, plaintext, aad):
    from shared.crypto_utils import aesgcm_encrypt
    return aesgcm_encrypt(key, plaintext, aad)


# ===========================================================================
# 4. 服务端核心：挑战-响应登录 + nonce 重放
# ===========================================================================
class TestLoginChallenge(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        from server.user.manager import UserManager
        self.um = UserManager({})
        from server.rate_limit.token_bucket import RateLimiter
        self.rl = RateLimiter({})

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _make_server(self):
        from server.chat.server import ChatServer
        srv = ChatServer.__new__(ChatServer)
        srv.config = {}
        srv.user_manager = self.um
        srv.rate_limiter = self.rl
        # 离线 store 替身
        class _OS:
            def update_deadman_checkin(inner, u): pass
            def get_messages(inner, u): return []
            def clear_messages(inner, u): pass
        srv.offline_store = _OS()
        class _GM:
            def flush_pending_group_keys(inner, u): return 0
        srv.group_manager = _GM()
        srv.connections = {}
        srv.lock = __import__("threading").Lock()
        srv.msg_sender_map = {}
        srv.msg_lock = __import__("threading").Lock()
        import threading
        srv.stats = {}
        srv.node_id = "cc" * 20
        srv.cross_server = None
        # nonce db
        import sqlite3
        srv._nonce_db_path = os.path.join(self.data_dir, "replay_nonces.db")
        srv._NONCE_CACHE_MAX = 10000
        from shared.protocol import REPLAY_WINDOW_SEC
        srv._REPLAY_WINDOW = REPLAY_WINDOW_SEC
        srv.nonce_lock = threading.Lock()
        from collections import OrderedDict
        srv.recent_nonces = OrderedDict()
        srv._init_nonce_db()
        srv._sent = []
        srv._send_raw = lambda conn, msg: srv._sent.append(msg)
        return srv

    def test_login_signature_and_replay(self):
        e_priv_b64, e_pub_b64 = generate_ed25519_keypair()
        x_priv_b64, x_pub_b64 = generate_x25519_keypair()
        uuid_str = "uuid-login-test"
        self.um.register_user(uuid_str, x_pub_b64, e_pub_b64, "127.0.0.1")

        srv = self._make_server()
        priv_obj = load_ed25519_private(e_priv_b64)

        def do_login(nonce, pub_for_sig=None):
            sig_data = json.dumps({
                "type": "LOGIN", "uuid": uuid_str,
                "ed25519_public": e_pub_b64, "nonce": nonce,
            }, sort_keys=True).encode()
            sig = sign_data(priv_obj, sig_data)
            conn = FakeConn()
            srv._handle_login(conn, {
                "uuid": uuid_str, "ed25519_public": e_pub_b64,
                "signature": sig, "nonce": nonce,
            })
            return conn

        # 1) 正确签名 → 登录成功
        c1 = do_login("nonce-good-1")
        self.assertTrue(c1.authenticated)
        self.assertTrue(any(m.get("type") == "LOGIN_OK" for m in srv._sent))

        # 2) 重放同一 nonce → 拒绝
        srv._sent.clear()
        c2 = do_login("nonce-good-1")
        self.assertFalse(c2.authenticated)
        self.assertTrue(any(m.get("type") == "ERROR"
                            and "Replay" in m.get("message", "") for m in srv._sent))

        # 3) 错误签名 → 拒绝
        bad_priv_b64, _ = generate_ed25519_keypair()
        bad_obj = load_ed25519_private(bad_priv_b64)
        sig_data = json.dumps({
            "type": "LOGIN", "uuid": uuid_str,
            "ed25519_public": e_pub_b64, "nonce": "nonce-good-2",
        }, sort_keys=True).encode()
        bad_sig = sign_data(bad_obj, sig_data)
        conn = FakeConn()
        srv._handle_login(conn, {
            "uuid": uuid_str, "ed25519_public": e_pub_b64,
            "signature": bad_sig, "nonce": "nonce-good-2",
        })
        self.assertFalse(conn.authenticated)


# ===========================================================================
# 5. 管理员命令分发
# ===========================================================================
class TestAdminCommands(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        from server.user.manager import UserManager
        from server.rate_limit.token_bucket import RateLimiter
        from server.chat.offline import OfflineStore
        from server.admin.auth import AdminAuth
        from server.admin.commands import AdminCommandHandler
        self.um = UserManager({})
        self.rl = RateLimiter({})
        self.os_store = OfflineStore({})
        self.auth = AdminAuth({})

        class FakeServer:
            pass
        self.srv = FakeServer()
        self.srv.user_manager = self.um
        self.srv.rate_limiter = self.rl
        self.srv.offline_store = self.os_store
        self.srv.admin_auth = self.auth
        self.srv.connections = {}
        self.srv.config = {}
        self.srv.dht_node = None
        self.srv.cross_server = mock.Mock()
        self.srv.cross_server.reset_tofu_pins = mock.Mock()
        self.srv.get_stats = lambda: {"online": 0}
        self.srv.broadcast = lambda text: None
        self.handler = AdminCommandHandler(self.srv, self.srv.config)

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_list_banned(self):
        # 造一个用户并封禁
        res = self.um.create_user_for_admin("victim")
        self.um.ban_user(res["uuid"])
        out = self.handler.execute("LIST_BANNED", {}, None)
        self.assertTrue(out["ok"] if "ok" in out else True)
        self.assertGreaterEqual(out["count"], 1)

    def test_mute_and_unmute(self):
        res = self.um.create_user_for_admin("muted")
        u = res["uuid"]
        self.handler.execute("MUTE_USER", {"uuid": u, "duration_sec": 600}, None)
        self.assertTrue(self.um.is_muted(u))
        out = self.handler.execute("UNMUTE_USER", {"uuid": u}, None)
        self.assertTrue(out["ok"])
        self.assertFalse(self.um.is_muted(u))

    def test_reset_tofu(self):
        out = self.handler.execute("RESET_TOFU", {}, None)
        self.assertTrue(out["ok"])
        self.srv.cross_server.reset_tofu_pins.assert_called_once()

    def test_stats(self):
        out = self.handler.execute("STATS", {}, None)
        self.assertTrue(out["ok"])
        self.assertIn("stats", out)

    def test_unknown_command(self):
        out = self.handler.execute("NO_SUCH_CMD", {}, None)
        self.assertFalse(out["ok"])


# ===========================================================================
# 6. 论坛评论：树状 / 墓碑 / 悬挂 / 跨帖子拒绝
# ===========================================================================
class TestForumComments(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        import server.forum.database as fdb
        fdb._db_instance = None
        self.node = "dd" * 20
        from server.forum import posts as pm
        self.p1 = pm.create_post(
            self.node, "author-1", "标题A", "正文A", ["t"],
            "asig", "ssig", "pub")
        self.p2 = pm.create_post(
            self.node, "author-2", "标题B", "正文B", [],
            "asig", "ssig", "pub")

    def tearDown(self):
        import server.forum.database as fdb
        fdb._db_instance = None
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _c(self, parent=""):
        from server.forum.comments import create_comment
        return create_comment(
            self.node, self.p1["id"], "au", "内容", parent,
            "csig", "ssig", "pub")

    def test_tree_flat_list_and_reply_to(self):
        root = self._c()
        reply = self._c(root["id"])
        deep = self._c(reply["id"])
        from server.forum.comments import list_comments
        listing = list_comments(self.p1["id"])
        ids = {c["id"] for c in listing["comments"]}
        self.assertEqual(ids, {root["id"], reply["id"], deep["id"]})
        reply_row = next(c for c in listing["comments"] if c["id"] == reply["id"])
        self.assertEqual(reply_row["reply_to_username"], "au")

    def test_tombstone_no_cascade(self):
        root = self._c()
        reply = self._c(root["id"])
        from server.forum.comments import delete_comment, list_comments
        delete_comment(root["id"], "au", is_admin=True)
        listing = list_comments(self.p1["id"])
        ids = {c["id"] for c in listing["comments"]}
        # 子评论仍在（不级联）
        self.assertIn(reply["id"], ids)
        # 子评论的 reply_to 显示已删除用户
        reply_row = next(c for c in listing["comments"] if c["id"] == reply["id"])
        self.assertEqual(reply_row["reply_to_username"], "已删除用户")

    def test_reject_hanging_reply(self):
        from server.forum.comments import create_comment
        c = create_comment(
            self.node, self.p1["id"], "au", "内容", "nonexistent-parent",
            "csig", "ssig", "pub")
        self.assertIsNone(c)

    def test_reject_cross_post_reply(self):
        root_in_p1 = self._c()
        from server.forum.comments import create_comment
        # 试图在 p2 下回复 p1 的评论
        c = create_comment(
            self.node, self.p2["id"], "au", "内容", root_in_p1["id"],
            "csig", "ssig", "pub")
        self.assertIsNone(c)


# ===========================================================================
# 7. 论坛：热度 sign(0)=0 与 FTS5 LIKE 降级
# ===========================================================================
class TestForumHeatAndSearch(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        import server.forum.database as fdb
        fdb._db_instance = None

    def tearDown(self):
        import server.forum.database as fdb
        fdb._db_instance = None
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_sign_zero_explicit(self):
        from server.forum.posts import calculate_hot_score
        # net_votes=0 时投票部分必须为 0（即使 log10(1)=0 也不能乘 -1）
        h = calculate_hot_score(0, 0, 1700000000)
        import math
        expected = 0 + 0.8 * math.log10(1) + 1700000000 / 45000.0
        self.assertAlmostEqual(h, expected, places=2)

    def test_search_like_fallback(self):
        from server.forum import posts as pm
        node = "ee" * 20
        pm.create_post(node, "au", "独特关键词苹果", "正文含 banana", ["t"],
                       "s", "s", "p")
        results = pm.search_posts("苹果")
        self.assertGreaterEqual(len(results), 1)


if __name__ == "__main__":
    # 运行前清空 forum db 单例
    import server.forum.database as _fdb
    _fdb._db_instance = None
    unittest.main(verbosity=2)

"""
随机数据包（诱饵包）功能测试。

覆盖：
  - 配置默认关闭，间隔默认 30~300 秒
  - SET_DECOY / DECOY_ON / DECOY_OFF / DECOY_STATUS 管理员命令
  - 诱饵包外层与真实 RELAY_MSG 逐字段同构（同一 type、同字段、等长取值）
  - 内容层用对端 transport_key 做 AES-GCM 密封，每次密文不同
  - 接收方识别 dummy 后静默丢弃（不投递、不写离线队列、不回执）
  - 真实 RELAY_MSG 不被误判、收发不受影响
  - 每轮随机选一台已认证对端；间隔采样落在配置范围且非固定
  - set_decoy 参数校验、守护线程可干净退出

运行方式：python3 test_decoy.py
"""

import os
import sys
import json
import time
import tempfile
import shutil
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 所有数据目录相关模块必须在设置 SPIDER_DATA_DIR 后再导入
_TMP = tempfile.mkdtemp(prefix="spider_decoy_test_")
os.environ["SPIDER_DATA_DIR"] = _TMP

from server.config.loader import get_data_dir  # noqa: E402
import server.config.loader as _cfg_loader  # noqa: E402
_env_data_dir = lambda: os.environ["SPIDER_DATA_DIR"]
_cfg_loader.get_data_dir = _env_data_dir
# cross_server 在导入时绑定了 get_data_dir / get_server_keys / get_node_id，
# 这里同步 patch 其模块级引用。
import server.chat.cross_server as _cmod  # noqa: E402
_cmod.get_data_dir = _env_data_dir

from shared.crypto_utils import (  # noqa: E402
    generate_ed25519_keypair, generate_x25519_keypair,
    aesgcm_decrypt,
)
from shared.protocol import DECOY_MSG  # noqa: E402

PEER_TK = b"\x11" * 32
REAL_RELAY_KEYS = {"type", "from_uuid", "to_uuid", "encrypted_payload",
                   "signature", "source_server", "timestamp"}


def _fresh_data_dir():
    d = tempfile.mkdtemp(prefix="spider_decoy_test_")
    os.environ["SPIDER_DATA_DIR"] = d
    return d


def _make_fake_server_keys():
    e_priv, e_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    return {
        "server_ed25519_priv": e_priv,
        "server_ed25519_pub": e_pub,
        "server_x25519_priv": x_priv,
        "server_x25519_pub": x_pub,
    }


def _make_relay(config=None):
    keys = _make_fake_server_keys()
    node_id = "11" * 20
    p1 = mock.patch.object(_cmod, "get_server_keys", lambda: keys)
    p2 = mock.patch.object(_cmod, "get_node_id", lambda: node_id)
    p1.start()
    p2.start()
    from server.chat.cross_server import CrossServerRelay
    relay = CrossServerRelay(config or {}, chat_server=None)
    return relay, (p1, p2)


def _inject_peer(relay, node_id="peer-1", transport_key=PEER_TK):
    with relay.peers_lock:
        relay.peers[node_id] = {
            "sock": None,
            "addr": ("127.0.0.1", 11111),
            "last_seen": time.time(),
            "authenticated": True,
            "node_id": node_id,
            "ed25519_pubkey": "",
            "transport_key": transport_key,
        }


class TestDecoyDefaultConfig(unittest.TestCase):
    def test_default_off(self):
        from server.config.loader import DEFAULT_CONFIG, load_config
        self.assertIs(DEFAULT_CONFIG["decoy_enabled"], False)
        cfg = load_config()
        self.assertIs(cfg["decoy_enabled"], False)
        self.assertEqual(cfg["decoy_min_interval_sec"], 30)
        self.assertEqual(cfg["decoy_max_interval_sec"], 300)


class TestDecoyAdminCommands(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        from server.user.manager import UserManager
        from server.rate_limit.token_bucket import RateLimiter
        from server.chat.offline import OfflineStore
        from server.admin.commands import AdminCommandHandler
        self.um = UserManager({})
        self.rl = RateLimiter({})
        self.os_store = OfflineStore({})

        class FakeServer:
            pass
        self.srv = FakeServer()
        self.srv.user_manager = self.um
        self.srv.rate_limiter = self.rl
        self.srv.offline_store = self.os_store
        self.srv.connections = {}
        self.srv.config = {}
        self.srv.cross_server = mock.Mock()
        self.srv.cross_server.set_decoy = mock.Mock(return_value=True)
        self.srv.cross_server.decoy_status = mock.Mock(return_value={
            "enabled": True, "interval_min": 30, "interval_max": 300,
            "last_sent_time": 0.0, "sent_count": 0, "received_count": 0,
            "known_peers": 1,
        })
        self.handler = AdminCommandHandler(self.srv, self.srv.config)

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_on_status_off(self):
        out = self.handler.execute("DECOY_ON", {}, None)
        self.assertTrue(out["ok"])
        self.srv.cross_server.set_decoy.assert_called_with(True, 30.0, 300.0)
        self.assertIs(self.srv.config["decoy_enabled"], True)

        st = self.handler.execute("DECOY_STATUS", {}, None)
        self.assertTrue(st["ok"])
        self.assertEqual(st["status"]["interval_min"], 30)
        self.assertEqual(st["status"]["interval_max"], 300)

        off = self.handler.execute("DECOY_OFF", {}, None)
        self.assertTrue(off["ok"])
        self.assertIs(self.srv.config["decoy_enabled"], False)

    def test_on_bad_interval_rejected(self):
        self.srv.cross_server.set_decoy = mock.Mock(return_value=False)
        out = self.handler.execute("DECOY_ON", {"interval_min": 100, "interval_max": 10}, None)
        self.assertFalse(out["ok"])


class TestDecoyIndistinguishableEnvelope(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        self.relay, self._patches = _make_relay()
        _inject_peer(self.relay, "peer-1", PEER_TK)

    def tearDown(self):
        try:
            self.relay.stop()
        except Exception:
            pass
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_envelope_matches_relay_msg(self):
        env = self.relay._build_decoy_message("peer-1")
        # 外层与真实 RELAY_MSG 逐字段一致：同一 type、同字段集合
        self.assertEqual(env["type"], "RELAY_MSG")
        self.assertEqual(set(env.keys()), REAL_RELAY_KEYS)
        # uuid 长度与真实 uuid 一致（36），signature 长度与 Ed25519 签名一致（88）
        self.assertEqual(len(env["from_uuid"]), 36)
        self.assertEqual(len(env["to_uuid"]), 36)
        self.assertEqual(len(env["signature"]), 88)
        self.assertTrue(env["source_server"])
        self.assertIsInstance(env["timestamp"], int)
        # 外层 from/to 与内层 encrypted_payload 一致，与真实消息相同
        self.assertEqual(env["from_uuid"], env["encrypted_payload"]["from_uuid"])
        self.assertEqual(env["to_uuid"], env["encrypted_payload"]["to_uuid"])

    def test_content_sealed_and_random(self):
        e1 = self.relay._build_decoy_message("peer-1")
        e2 = self.relay._build_decoy_message("peer-1")
        # 内容层是 transport_key 密封密文，而非明文
        sealed1 = e1["encrypted_payload"]
        self.assertIn("ciphertext", sealed1)
        self.assertIn("nonce", sealed1)
        # 无密钥者（错误 key）无法解密
        self.assertIsNone(aesgcm_decrypt(b"\x00" * 32, sealed1["nonce"],
                                         sealed1["ciphertext"], sealed1["tag"],
                                         sealed1.get("aad", "")))
        # 持有 transport_key 者可解出 dummy 标记与随机载荷
        pt = aesgcm_decrypt(PEER_TK, sealed1["nonce"], sealed1["ciphertext"],
                            sealed1["tag"], sealed1.get("aad", ""))
        inner = json.loads(pt.decode())
        self.assertTrue(inner["dummy"])
        self.assertGreater(len(inner["payload"]), 10)
        # 每次密文不同
        self.assertNotEqual(sealed1["ciphertext"], e2["encrypted_payload"]["ciphertext"])

    def test_inner_payload_key_set_matches_real_client_message(self):
        # 用真实客户端密封函数生成一条消息，键集必须与诱饵 encrypted_payload 完全一致
        import uuid as _uuid
        from client.crypto.encrypt import encrypt_message
        from shared.crypto_utils import generate_x25519_keypair, generate_ed25519_keypair
        x_priv, x_pub = generate_x25519_keypair()
        e_priv, e_pub = generate_ed25519_keypair()
        real = encrypt_message("hello", x_priv, x_pub, e_priv,
                               str(_uuid.uuid4()), str(_uuid.uuid4()))
        decoy = self.relay._build_decoy_message("peer-1")["encrypted_payload"]
        self.assertEqual(set(real.keys()), set(decoy.keys()),
                         f"键集不一致: 缺 {set(real)-set(decoy)} 多 {set(decoy)-set(real)}")
        # 取值特征对齐
        self.assertEqual(decoy["version"], 2)
        self.assertIsInstance(decoy["version"], int)
        self.assertEqual(len(decoy["from_uuid"]), 36)
        self.assertEqual(len(decoy["to_uuid"]), 36)
        self.assertEqual(len(decoy["ephemeral_pub"]), 44)
        self.assertEqual(len(decoy["signature"]), 88)
        self.assertIsInstance(decoy["fs_used"], bool)


class TestDecoySilentDrop(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        self.relay, self._patches = _make_relay()
        _inject_peer(self.relay, "peer-1", PEER_TK)
        self.fake_chat = mock.Mock()
        self.fake_chat._send_raw = mock.Mock()
        self.fake_chat.connections = {}
        self.fake_chat.rate_limiter = mock.Mock()
        self.fake_chat.rate_limiter.get_effective_rate = lambda u: 0.5
        self.fake_chat.rate_limiter.allow_with_rate = lambda u, r: True
        self.fake_chat.stats = {}
        self.fake_chat.offline_store = mock.Mock()
        self.fake_chat.offline_store.add_message = mock.Mock()
        self.relay.chat_server = self.fake_chat

    def tearDown(self):
        try:
            self.relay.stop()
        except Exception:
            pass
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_decoy_silently_dropped(self):
        decoy = self.relay._build_decoy_message("peer-1")
        before = self.relay._decoy_received
        self.relay._handle_interserver_message("peer-1", json.dumps(decoy))
        self.assertEqual(self.relay._decoy_received, before + 1)
        # 不投递、不写离线队列、不触发业务
        self.fake_chat._send_raw.assert_not_called()
        self.fake_chat.offline_store.add_message.assert_not_called()

    def test_real_relay_not_misrouted(self):
        # 真实中继内容用其它密钥密封：transport_key 解密失败，必须走正常投递路径
        from shared.crypto_utils import aesgcm_encrypt
        real_payload = aesgcm_encrypt(b"\x99" * 32, b'{"real":true}')
        real_relay = {
            "type": "RELAY_MSG",
            "from_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "to_uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "encrypted_payload": real_payload,
            "signature": "somesig",
            "source_server": "other",
            "timestamp": int(time.time()),
        }
        before = self.relay._decoy_received
        self.relay._handle_interserver_message("peer-1", json.dumps(real_relay))
        # 未被识别为诱饵
        self.assertEqual(self.relay._decoy_received, before)
        # 真实消息会尝试投递（这里 target 不存在，落到 offline_store）
        self.fake_chat.offline_store.add_message.assert_called()

    def test_unknown_type_ignored(self):
        before = self.relay._decoy_received
        self.relay._handle_interserver_message("peer-1", json.dumps({"type": "WEIRD"}))
        self.relay._handle_interserver_message("peer-1", "not-json{{{")
        self.assertEqual(self.relay._decoy_received, before)


class TestDecoyRandomTarget(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        self.relay, self._patches = _make_relay()
        self.sent_calls = []
        self._orig_send = self.relay._send_to_peer

        def recording_send(nid, msg):
            self.sent_calls.append((nid, msg))
            return True
        self.relay._send_to_peer = recording_send
        _inject_peer(self.relay, "peer-A", PEER_TK)
        _inject_peer(self.relay, "peer-B", PEER_TK)
        _inject_peer(self.relay, "peer-C", PEER_TK)

    def tearDown(self):
        try:
            self.relay.set_decoy(False, 1, 2)
        except Exception:
            pass
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_picks_one_random_peer_per_round(self):
        self.relay.set_decoy(True, 0.01, 0.05)
        time.sleep(0.5)
        self.relay.set_decoy(False, 1, 2)
        self.assertGreaterEqual(len(self.sent_calls), 1)
        targets = {nid for nid, _ in self.sent_calls}
        # 每轮只发一台，且在多轮中可能落在不同 peer 上
        for nid, msg in self.sent_calls:
            self.assertIn(nid, {"peer-A", "peer-B", "peer-C"})
            self.assertEqual(msg["type"], "RELAY_MSG")
            self.assertEqual(set(msg.keys()), REAL_RELAY_KEYS)
        self.assertGreaterEqual(self.relay._decoy_sent, 1)


class TestDecoyIntervalSampling(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        self.relay, self._patches = _make_relay()
        _inject_peer(self.relay, "peer-1", PEER_TK)

    def tearDown(self):
        try:
            self.relay.stop()
        except Exception:
            pass
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_draws_in_range_and_non_fixed(self):
        drawn = []
        orig_uniform = _cmod.random.uniform

        def spy(a, b):
            v = orig_uniform(a, b)
            if abs(a - 30.0) < 1e-9 and abs(b - 300.0) < 1e-9:
                drawn.append(v)
            return 0.001  # 让循环快速唤醒以收集多次采样

        # 先装 spy 再启动线程：首轮等待即被压缩为 0.001s
        _cmod.random.uniform = spy
        try:
            self.relay.set_decoy(True, 30, 300)
            time.sleep(0.4)
        finally:
            _cmod.random.uniform = orig_uniform
            self.relay.set_decoy(False, 30, 300)
        self.assertGreaterEqual(len(drawn), 3)
        self.assertTrue(all(30.0 <= v <= 300.0 for v in drawn))
        self.assertGreater(len({round(v, 3) for v in drawn}), 1, "间隔不应固定")


class TestDecoyLifecycle(unittest.TestCase):
    def setUp(self):
        self.data_dir = _fresh_data_dir()
        self.relay, self._patches = _make_relay()

    def tearDown(self):
        try:
            self.relay.stop()
        except Exception:
            pass
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_illegal_params_rejected(self):
        self.assertFalse(self.relay.set_decoy(True, 0, 10))
        self.assertFalse(self.relay.set_decoy(True, -1, 10))
        self.assertFalse(self.relay.set_decoy(True, 10, 10))
        self.assertFalse(self.relay.set_decoy(True, 100, 10))

    def test_stop_exits_quickly(self):
        _inject_peer(self.relay, "peer-1", PEER_TK)
        self.relay.set_decoy(True, 0.01, 0.05)
        t0 = time.time()
        self.relay.stop()
        self.assertLess(time.time() - t0, 1.0)
        self.assertFalse(self.relay._decoy_thread.is_alive())


if __name__ == "__main__":
    unittest.main(verbosity=2)

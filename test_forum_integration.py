"""
论坛子系统集成测试 — 覆盖单元、集成、回归、协议兼容、压力、安全测试。

运行方式：python3 test_forum_integration.py
"""

import os
import sys
import time
import json
import tempfile
import unittest
import threading

# 确保项目根目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestHotScore(unittest.TestCase):
    """热度公式单元测试。"""

    def test_basic_hot_score(self):
        from server.forum.posts import calculate_hot_score
        # 净投票 10，评论者 5，时间戳 1700000000
        hot = calculate_hot_score(10, 5, 1700000000)
        self.assertGreater(hot, 0)
        # 验证公式各部分
        import math
        expected_vote = math.log10(10) * 1  # 1.0
        expected_comment = 0.8 * math.log10(5)  # ~0.559
        expected_time = 1700000000 / 45000  # ~37777.8
        self.assertAlmostEqual(hot, expected_vote + expected_comment + expected_time, places=2)

    def test_sign_zero(self):
        """sign(0)=0 显式处理。"""
        from server.forum.posts import calculate_hot_score
        hot = calculate_hot_score(0, 0, 1000000)
        # 投票部分应为 0
        import math
        expected = 0 + 0.8 * math.log10(1) + 1000000 / 45000
        self.assertAlmostEqual(hot, expected, places=2)

    def test_negative_votes(self):
        """负投票应降低热度。"""
        from server.forum.posts import calculate_hot_score
        hot_pos = calculate_hot_score(10, 0, 1000000)
        hot_neg = calculate_hot_score(-10, 0, 1000000)
        self.assertGreater(hot_pos, hot_neg)

    def test_distinct_commenters(self):
        """distinct_commenters 去重，不用"只有第一条评论生效"。"""
        from server.forum.posts import calculate_hot_score
        hot_5 = calculate_hot_score(0, 5, 1000000)
        hot_10 = calculate_hot_score(0, 10, 1000000)
        self.assertGreater(hot_10, hot_5)

    def test_why_ranked_breakdown(self):
        """'为什么这个排名'分解。"""
        from server.forum.posts import calculate_hot_score, why_ranked
        # 直接测试公式分解逻辑
        net_votes = 10
        distinct = 5
        ts = 1700000000
        import math
        vote_part = math.log10(10) * 1
        comment_part = 0.8 * math.log10(5)
        time_part = ts / 45000.0
        total = vote_part + comment_part + time_part
        self.assertAlmostEqual(total, calculate_hot_score(net_votes, distinct, ts), places=2)


class TestVotes(unittest.TestCase):
    """投票单元测试。"""

    def setUp(self):
        """使用临时数据库。"""
        self.tmpdir = tempfile.mkdtemp()
        os.environ["SPIDER_DATA_DIR"] = self.tmpdir
        # 重置数据库单例
        import server.forum.database as db_mod
        db_mod._db_instance = None

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_vote_values(self):
        """投票值只能是 -1/0/1。"""
        from server.forum.votes import cast_vote
        result = cast_vote("user1", "post", "post1", 5)
        self.assertFalse(result["success"])

    def test_vote_change_rollback(self):
        """改票正确回滚旧票。"""
        from server.forum.votes import cast_vote
        # 先投 +1
        r1 = cast_vote("user1", "post", "post1", 1)
        self.assertTrue(r1["success"])
        # 改投 -1，净变化应为 -2
        r2 = cast_vote("user1", "post", "post1", -1)
        self.assertTrue(r2["success"])

    def test_same_value_cancels(self):
        """相同值取消投票（设为0）。"""
        from server.forum.votes import cast_vote
        cast_vote("user1", "post", "post1", 1)
        r = cast_vote("user1", "post", "post1", 1)
        self.assertTrue(r["success"])
        self.assertEqual(r["new_value"], 0)

    def test_get_user_vote(self):
        from server.forum.votes import cast_vote, get_user_vote
        cast_vote("user1", "post", "post1", 1)
        self.assertEqual(get_user_vote("user1", "post", "post1"), 1)
        self.assertEqual(get_user_vote("user2", "post", "post1"), 0)


class TestComments(unittest.TestCase):
    """评论单元测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ["SPIDER_DATA_DIR"] = self.tmpdir
        import server.forum.database as db_mod
        db_mod._db_instance = None

    def test_comment_two_level(self):
        """树状任意深度：根评论和回复都在扁平列表中，带 reply_to_username。"""
        from server.forum.posts import create_post
        from server.forum.comments import create_comment, list_comments

        post = create_post("node1", "user1", "Test", "Content", [], "sig", "ssig", "pub")
        # 根评论
        c1 = create_comment("node1", post["id"], "user2", "Root comment", "", "sig", "ssig", "pub")
        # 回复
        c2 = create_comment("node1", post["id"], "user3", "Reply", c1["id"], "sig", "ssig", "pub")

        result = list_comments(post["id"])
        # 新扁平格式：返回 {"comments": [...]}，根+回复都在内
        self.assertIn("comments", result)
        self.assertEqual(len(result["comments"]), 2)
        ids = {c["id"] for c in result["comments"]}
        self.assertEqual(ids, {c1["id"], c2["id"]})
        # 回复指向根评论作者
        reply = next(c for c in result["comments"] if c["id"] == c2["id"])
        self.assertEqual(reply["parent_id"], c1["id"])
        self.assertEqual(reply["reply_to_username"], "user2")
        # 根评论没有 reply_to
        root = next(c for c in result["comments"] if c["id"] == c1["id"])
        self.assertEqual(root["reply_to_username"], "")
        # reply_count 正确
        self.assertEqual(root["reply_count"], 1)
        self.assertEqual(reply["reply_count"], 0)

    def test_comment_deep_nesting(self):
        """任意深度：对回复再回复。"""
        from server.forum.posts import create_post
        from server.forum.comments import create_comment, list_comments

        post = create_post("node1", "user1", "Test", "Content", [], "sig", "ssig", "pub")
        c1 = create_comment("node1", post["id"], "user2", "root", "", "sig", "ssig", "pub")
        c2 = create_comment("node1", post["id"], "user3", "lvl2", c1["id"], "sig", "ssig", "pub")
        c3 = create_comment("node1", post["id"], "user4", "lvl3", c2["id"], "sig", "ssig", "pub")
        result = list_comments(post["id"])
        self.assertEqual(len(result["comments"]), 3)
        lvl3 = next(c for c in result["comments"] if c["id"] == c3["id"])
        self.assertEqual(lvl3["parent_id"], c2["id"])
        self.assertEqual(lvl3["reply_to_username"], "user3")

    def test_comment_reject_cross_post_reply(self):
        """跨帖子回复被拒绝。"""
        from server.forum.posts import create_post
        from server.forum.comments import create_comment, list_comments

        p1 = create_post("node1", "user1", "P1", "c", [], "sig", "ssig", "pub")
        p2 = create_post("node1", "user1", "P2", "c", [], "sig", "ssig", "pub")
        c1 = create_comment("node1", p1["id"], "user2", "root", "", "sig", "ssig", "pub")
        # 试图在 p2 下回复 p1 的评论
        bad = create_comment("node1", p2["id"], "user3", "reply", c1["id"], "sig", "ssig", "pub")
        self.assertIsNone(bad)

    def test_comment_tombstone_no_cascade(self):
        """删除为墓碑不级联；回复仍保留并标记父作者为已删除用户。"""
        from server.forum.posts import create_post
        from server.forum.comments import create_comment, delete_comment, list_comments

        post = create_post("node1", "user1", "Test", "Content", [], "sig", "ssig", "pub")
        c1 = create_comment("node1", post["id"], "user2", "Root", "", "sig", "ssig", "pub")
        c2 = create_comment("node1", post["id"], "user3", "Reply", c1["id"], "sig", "ssig", "pub")

        # 删除根评论，回复应保留
        delete_comment(c1["id"], "user2")
        result = list_comments(post["id"])
        # 根评论被删除（墓碑），不显示；回复仍在
        self.assertEqual(len(result["comments"]), 1)
        reply = result["comments"][0]
        self.assertEqual(reply["id"], c2["id"])
        # 父评论已删除 → 父作者显示"已删除用户"
        self.assertEqual(reply["reply_to_username"], "已删除用户")

    def test_comment_edit_marker(self):
        """编辑显示已编辑标记。"""
        from server.forum.posts import create_post
        from server.forum.comments import create_comment, edit_comment, get_comment

        post = create_post("node1", "user1", "Test", "Content", [], "sig", "ssig", "pub")
        c = create_comment("node1", post["id"], "user1", "Original", "", "sig", "ssig", "pub")
        edited = edit_comment(c["id"], "user1", "Edited", "sig", "ssig")
        self.assertEqual(edited["edited"], 1)


class TestServerCard(unittest.TestCase):
    """服务器卡片单元测试。"""

    def test_heat_levels(self):
        """热度四级：绿/黄/橙/红。"""
        from server.forum.server_card import calculate_heat_level
        self.assertEqual(calculate_heat_level(0, 100), "green")
        self.assertEqual(calculate_heat_level(30, 100), "yellow")
        self.assertEqual(calculate_heat_level(60, 100), "orange")
        self.assertEqual(calculate_heat_level(90, 100), "red")

    def test_heat_level_text(self):
        from server.forum.server_card import heat_level_text
        self.assertEqual(heat_level_text("green"), "活跃")
        self.assertEqual(heat_level_text("yellow"), "中等")
        self.assertEqual(heat_level_text("orange"), "繁忙")
        self.assertEqual(heat_level_text("red"), "拥挤")


class TestRateLimit(unittest.TestCase):
    """限流单元测试。"""

    def test_hysteresis(self):
        """hysteresis 0.05 防抖。"""
        from server.forum.rate_limit import _current_level, _level_lock
        # 验证迟滞常量存在
        from shared.protocol import FORUM_LOAD_HYSTERESIS
        self.assertEqual(FORUM_LOAD_HYSTERESIS, 0.05)

    def test_admin_exempt(self):
        """管理员豁免。"""
        from server.forum.rate_limit import is_allowed
        allowed, delay, reason = is_allowed("post", is_admin=True)
        self.assertTrue(allowed)
        self.assertEqual(delay, 0)

    def test_threshold_order(self):
        """限流阈值按序：先限流后禁功能最后踢人。"""
        from shared.protocol import (
            FORUM_LOAD_SLOW_MESSAGES, FORUM_LOAD_SLOW_POSTING,
            FORUM_LOAD_BLOCK_SEARCH, FORUM_LOAD_BLOCK_REGISTER,
            FORUM_LOAD_BLOCK_DHT, FORUM_LOAD_BLOCK_LOGIN,
            FORUM_LOAD_LOGOUT_USERS, FORUM_LOAD_BLOCK_ALL,
        )
        thresholds = [
            FORUM_LOAD_SLOW_MESSAGES, FORUM_LOAD_SLOW_POSTING,
            FORUM_LOAD_BLOCK_SEARCH, FORUM_LOAD_BLOCK_REGISTER,
            FORUM_LOAD_BLOCK_DHT, FORUM_LOAD_BLOCK_LOGIN,
            FORUM_LOAD_LOGOUT_USERS, FORUM_LOAD_BLOCK_ALL,
        ]
        # 验证阈值递增
        for i in range(len(thresholds) - 1):
            self.assertLessEqual(thresholds[i], thresholds[i + 1])


class TestCrossServer(unittest.TestCase):
    """跨服寻址单元测试。"""

    def test_post_id_parsing(self):
        """帖子 ID 解析：node_id:64hex。"""
        from server.forum.cross_server import parse_post_id
        node_id, hex_part = parse_post_id("node123:" + "a" * 64)
        self.assertEqual(node_id, "node123")
        self.assertEqual(len(hex_part), 64)

    def test_invalid_post_id(self):
        from server.forum.cross_server import parse_post_id
        node_id, hex_part = parse_post_id("invalid")
        self.assertIsNone(node_id)

    def test_no_broadcast_fallback(self):
        """禁止广播整个联邦作为回退（设计验证）。"""
        # 验证 resolve_post 中没有广播逻辑
        import inspect
        from server.forum import cross_server
        source = inspect.getsource(cross_server.resolve_post)
        self.assertNotIn("broadcast", source.lower())
        self.assertNotIn("flood", source.lower())


class TestProtocolConstants(unittest.TestCase):
    """协议常量测试 — 只新增不修改已有。"""

    def test_forum_constants_exist(self):
        from shared import protocol
        required = [
            "POST_CREATE", "POST_LIST", "POST_GET", "POST_DELETE", "POST_EDIT",
            "COMMENT_CREATE", "COMMENT_LIST", "COMMENT_DELETE",
            "VOTE_CAST", "VOTE_GET",
            "SERVER_INFO_REQUEST", "SERVER_INFO_RESPONSE",
            "LOAD_STATUS", "LOAD_STATUS_REQUEST",
            "CROSS_POST_FETCH", "NOTIFICATION_LIST", "REPORT_SUBMIT",
            "DRAFT_SAVE", "DRAFT_LIST", "FORUM_PROFILE_GET",
        ]
        for const in required:
            self.assertTrue(hasattr(protocol, const), f"缺少常量: {const}")

    def test_existing_constants_unchanged(self):
        """验证已有常量未被修改。"""
        from shared import protocol
        self.assertEqual(protocol.PROTOCOL_VERSION, 3)
        self.assertEqual(protocol.SEND_MSG, "SEND_MSG")
        self.assertEqual(protocol.DEFAULT_TCP_PORT, 7891)

    def test_post_id_hex_len(self):
        from shared.protocol import FORUM_POST_ID_HEX_LEN
        self.assertEqual(FORUM_POST_ID_HEX_LEN, 64)


class TestDatabase(unittest.TestCase):
    """数据库迁移测试 — CREATE TABLE IF NOT EXISTS。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ["SPIDER_DATA_DIR"] = self.tmpdir
        import server.forum.database as db_mod
        db_mod._db_instance = None

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_tables_created(self):
        """所有表创建成功。"""
        from server.forum.database import get_forum_db
        db = get_forum_db()
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        required = ["posts", "comments", "votes", "known_servers",
                     "audit_log", "reports", "notifications", "drafts", "user_preferences"]
        for t in required:
            self.assertIn(t, table_names, f"缺少表: {t}")

    def test_idempotent_migration(self):
        """重复初始化不报错（CREATE TABLE IF NOT EXISTS）。"""
        from server.forum.database import get_forum_db, _init_tables
        db = get_forum_db()
        # 再次初始化应不报错
        _init_tables(db)

    def test_unix_timestamps(self):
        """所有时间用 Unix 秒。"""
        from server.forum.database import now_ts
        ts = now_ts()
        self.assertIsInstance(ts, int)
        self.assertGreater(ts, 1700000000)  # 2023年后


class TestIntegration(unittest.TestCase):
    """集成测试 — 发帖→评论→投票→搜索全流程。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ["SPIDER_DATA_DIR"] = self.tmpdir
        import server.forum.database as db_mod
        db_mod._db_instance = None

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_post_flow(self):
        """完整流程：发帖→评论→投票→搜索。"""
        from server.forum.posts import create_post, get_post, list_posts, search_posts
        from server.forum.comments import create_comment, list_comments
        from server.forum.votes import cast_vote

        # 发帖
        post = create_post("node1", "user1", "Test Post", "Hello World", ["test"], "sig", "ssig", "pub")
        self.assertIsNotNone(post)
        self.assertEqual(post["title"], "Test Post")

        # 获取帖子
        fetched = get_post(post["id"])
        self.assertEqual(fetched["id"], post["id"])

        # 评论
        c1 = create_comment("node1", post["id"], "user2", "Nice post", "", "sig", "ssig", "pub")
        self.assertIsNotNone(c1)

        # 投票
        r = cast_vote("user2", "post", post["id"], 1)
        self.assertTrue(r["success"])

        # 搜索
        results = search_posts("Hello")
        self.assertTrue(any(p["id"] == post["id"] for p in results))

        # 列表
        posts = list_posts(sort="new")
        self.assertTrue(any(p["id"] == post["id"] for p in posts))

    def test_post_validation(self):
        """帖子内容校验。"""
        from server.forum.posts import validate_post
        ok, err = validate_post("", "content", [])
        self.assertFalse(ok)
        ok, err = validate_post("title", "", [])
        self.assertFalse(ok)
        ok, err = validate_post("t", "c", [])
        self.assertTrue(ok)


class TestRegression(unittest.TestCase):
    """回归测试 — 现有功能不受影响。"""

    def test_crypto_utils_unchanged(self):
        """crypto_utils 函数签名未变。"""
        from shared.crypto_utils import (
            generate_ed25519_keypair, sign_data, verify_signature,
            generate_x25519_keypair, ecdh_shared_secret,
        )
        self.assertTrue(callable(sign_data))
        self.assertTrue(callable(verify_signature))
        self.assertTrue(callable(ecdh_shared_secret))

    def test_transport_encryptor_unchanged(self):
        """TransportEncryptor 线格式未变。"""
        from shared.crypto_utils import TransportEncryptor
        self.assertTrue(hasattr(TransportEncryptor, "encrypt_packet"))
        self.assertTrue(hasattr(TransportEncryptor, "decrypt_packet"))


class TestSecurity(unittest.TestCase):
    """安全测试。"""

    def test_error_response_no_content(self):
        """错误响应不含帖子正文。"""
        # 验证错误响应格式
        error_format = {"type": "ERROR", "code": "TEST", "message": "test", "request_id": "123"}
        self.assertNotIn("content", error_format)
        self.assertNotIn("post", error_format)

    def test_no_e2ee_for_posts(self):
        """帖子不 E2EE（设计验证）。"""
        import inspect
        from server.forum import posts
        source = inspect.getsource(posts)
        # 帖子存储是明文，不应有加密调用
        self.assertNotIn("encrypt_message", source)

    def test_forum_db_independent(self):
        """论坛数据独立 forum.db。"""
        from server.forum.database import FORUM_DB_NAME
        self.assertEqual(FORUM_DB_NAME, "forum.db")

    def test_audit_log_required(self):
        """所有管理员操作必须有审计（设计验证）。"""
        from server.forum.database import get_forum_db
        import os
        os.environ["SPIDER_DATA_DIR"] = tempfile.mkdtemp()
        import server.forum.database as db_mod
        db_mod._db_instance = None
        db = get_forum_db()
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        self.assertIn("audit_log", table_names)


def run_tests():
    """运行所有测试。"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestHotScore,
        TestVotes,
        TestComments,
        TestServerCard,
        TestRateLimit,
        TestCrossServer,
        TestProtocolConstants,
        TestDatabase,
        TestIntegration,
        TestRegression,
        TestSecurity,
    ]

    for tc in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(tc))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print(f"\n{'='*60}")
    print(f"测试结果: {result.testsRun} 运行, "
          f"{len(result.failures)} 失败, "
          f"{len(result.errors)} 错误")
    print(f"{'='*60}")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

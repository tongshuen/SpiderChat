"""
论坛数据库层 — forum.db

独立数据库，通过 UUID 关联 users.db。
所有表使用 CREATE TABLE IF NOT EXISTS，支持迁移。
时间统一使用 Unix 秒。
"""

import os
import sqlite3
import threading
import time
from client.utils.config import get_data_dir

FORUM_DB_NAME = "forum.db"

# 数据库单例锁
_db_lock = threading.Lock()
_db_instance = None


def get_forum_db() -> sqlite3.Connection:
    """获取论坛数据库连接（单例，check_same_thread=False）。"""
    global _db_instance
    with _db_lock:
        if _db_instance is None:
            data_dir = os.environ.get("SPIDER_DATA_DIR") or get_data_dir()
            os.makedirs(data_dir, exist_ok=True)
            path = os.path.join(data_dir, FORUM_DB_NAME)
            _db_instance = sqlite3.connect(path, check_same_thread=False)
            _db_instance.row_factory = sqlite3.Row
            _db_instance.execute("PRAGMA journal_mode=WAL")
            _db_instance.execute("PRAGMA foreign_keys=ON")
            _init_tables(_db_instance)
        return _db_instance


def _init_tables(db: sqlite3.Connection):
    """初始化所有表（CREATE TABLE IF NOT EXISTS）。"""

    # 帖子表
    db.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id TEXT PRIMARY KEY,              -- {node_id}:{64hex}
            node_id TEXT NOT NULL,            -- 来源服务器 node_id
            author_uuid TEXT NOT NULL,        -- 作者 UUID
            title TEXT NOT NULL,              -- 标题
            content TEXT NOT NULL,            -- 正文（明文）
            tags TEXT DEFAULT '',             -- 逗号分隔标签
            author_signature TEXT NOT NULL,   -- 作者 Ed25519 签名
            server_signature TEXT NOT NULL,   -- 服务器 Ed25519 签名
            author_pubkey TEXT NOT NULL,      -- 作者公钥（用于验签）
            hot_score REAL DEFAULT 0,         -- 热度分
            net_votes INTEGER DEFAULT 0,      -- 净投票数
            upvotes INTEGER DEFAULT 0,
            downvotes INTEGER DEFAULT 0,
            comment_count INTEGER DEFAULT 0,
            distinct_commenters INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL,       -- Unix 秒
            updated_at INTEGER NOT NULL,
            edited INTEGER DEFAULT 0,          -- 是否编辑过
            deleted INTEGER DEFAULT 0,          -- 墓碑标记
            deleted_by TEXT DEFAULT '',         -- 删除者 UUID
            deleted_at INTEGER DEFAULT 0,
            pinned INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0
        )
    """)

    # 评论表（两层结构：parent_id 为空=根评论，非空=回复）
    db.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id TEXT PRIMARY KEY,              -- {node_id}:{64hex}
            post_id TEXT NOT NULL,             -- 所属帖子
            parent_id TEXT DEFAULT '',         -- 父评论 ID（空=根评论）
            author_uuid TEXT NOT NULL,
            content TEXT NOT NULL,
            author_signature TEXT NOT NULL,
            server_signature TEXT NOT NULL,
            author_pubkey TEXT NOT NULL,
            net_votes INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            edited INTEGER DEFAULT 0,
            deleted INTEGER DEFAULT 0,          -- 墓碑，不级联
            deleted_by TEXT DEFAULT '',
            deleted_at INTEGER DEFAULT 0,
            FOREIGN KEY (post_id) REFERENCES posts(id)
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_comments_author ON comments(author_uuid)")

    # 投票表（每用户每对象一票）
    db.execute("""
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uuid TEXT NOT NULL,
            target_type TEXT NOT NULL,         -- 'post' or 'comment'
            target_id TEXT NOT NULL,
            value INTEGER NOT NULL,            -- -1, 0, 1
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(user_uuid, target_type, target_id)
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_votes_target ON votes(target_type, target_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_votes_user ON votes(user_uuid)")

    # FTS5 全文搜索
    try:
        db.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
                title, content, tags,
                content='posts', content_rowid='rowid'
            )
        """)
    except sqlite3.OperationalError:
        pass  # FTS5 不可用时降级

    # 已知服务器表（服务器目录联邦）
    db.execute("""
        CREATE TABLE IF NOT EXISTS known_servers (
            node_id TEXT PRIMARY KEY,
            name TEXT DEFAULT 'Spider',
            avatar_b64 TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            host TEXT NOT NULL,
            tcp_port INTEGER NOT NULL,
            dht_port INTEGER DEFAULT 0,
            public_key TEXT NOT NULL,          -- 服务器 Ed25519 公钥
            signature TEXT NOT NULL,           -- 卡片签名
            online_count INTEGER DEFAULT 0,
            max_online INTEGER DEFAULT 100,
            heat_level TEXT DEFAULT 'green',
            heat_reference REAL DEFAULT 50,
            protocol_version INTEGER DEFAULT 3,
            software_version TEXT DEFAULT '1.0.0',
            updated_at INTEGER NOT NULL,
            first_seen_at INTEGER NOT NULL,
            last_connected_at INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0,
            status TEXT DEFAULT 'online',       -- online/offline/archived
            federated_with TEXT DEFAULT '',     -- 逗号分隔的联邦 node_id
            cached_until INTEGER DEFAULT 0
        )
    """)

    # 审计日志
    db.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_uuid TEXT NOT NULL,
            action TEXT NOT NULL,               -- 操作类型
            target_type TEXT DEFAULT '',
            target_id TEXT DEFAULT '',
            details TEXT DEFAULT '',             -- JSON 详情（不记录帖子正文）
            ip_address TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at)")

    # 举报表
    db.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_uuid TEXT NOT NULL,
            target_type TEXT NOT NULL,          -- post/comment/user
            target_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'pending',       -- pending/rejected/resolved
            resolved_by TEXT DEFAULT '',
            resolved_at INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL
        )
    """)

    # 通知表
    db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uuid TEXT NOT NULL,
            type TEXT NOT NULL,                  -- reply/mention/upvote/system
            title TEXT NOT NULL,
            content TEXT DEFAULT '',
            related_id TEXT DEFAULT '',
            is_read INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_uuid, is_read)")

    # 草稿表
    db.execute("""
        CREATE TABLE IF NOT EXISTS drafts (
            id TEXT PRIMARY KEY,
            user_uuid TEXT NOT NULL,
            title TEXT DEFAULT '',
            content TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            draft_type TEXT DEFAULT 'post',      -- post/comment
            reply_to TEXT DEFAULT '',
            updated_at INTEGER NOT NULL
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_drafts_user ON drafts(user_uuid)")

    # 用户偏好表
    db.execute("""
        CREATE TABLE IF NOT EXISTS user_preferences (
            user_uuid TEXT PRIMARY KEY,
            show_exact_online INTEGER DEFAULT 1,  -- 是否显示精确在线人数（管理员可关）
            default_sort TEXT DEFAULT 'hot',       -- hot/new/top
            theme TEXT DEFAULT 'dark',
            blocked_users TEXT DEFAULT '',          -- 逗号分隔
            muted_tags TEXT DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
    """)

    # 帖子索引
    db.execute("CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_uuid)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_posts_hot ON posts(hot_score DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_posts_node ON posts(node_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_posts_deleted ON posts(deleted)")

    db.commit()


def close_forum_db():
    """关闭论坛数据库连接。"""
    global _db_instance
    with _db_lock:
        if _db_instance:
            _db_instance.close()
            _db_instance = None


def now_ts() -> int:
    """当前 Unix 秒。"""
    return int(time.time())

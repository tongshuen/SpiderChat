"""
帖子管理 — CRUD、热度公式、搜索、游标分页。

热度公式：
  hot_score = log10(max(|net_votes|, 1)) * sign(net_votes)
            + w * log10(max(distinct_commenters, 1))
            + post_timestamp / 45000

  sign(0) = 0 显式处理
  w 默认 0.8
  distinct_commenters = 去重评论者数（不用"只有第一条评论生效"）
  post_timestamp = 发帖时间（Unix 秒）

后台每 5-10 分钟重算，查询直接排序。
"""

import math
import secrets
import time
import sqlite3
from server.forum.database import get_forum_db, now_ts
from shared.protocol import (
    FORUM_POST_ID_HEX_LEN, FORUM_MAX_TITLE_LEN, FORUM_MAX_CONTENT_LEN,
    FORUM_MAX_TAGS_PER_POST, FORUM_MAX_TAG_LEN, FORUM_DEFAULT_HOT_WEIGHT,
)


def generate_post_id(node_id: str) -> str:
    """生成帖子 ID：{node_id}:{64hex}"""
    return f"{node_id}:{secrets.token_hex(FORUM_POST_ID_HEX_LEN // 2)}"


def validate_post(title: str, content: str, tags: list) -> tuple:
    """校验帖子内容。返回 (ok, error_msg)。"""
    if not title or not title.strip():
        return False, "标题不能为空"
    if len(title) > FORUM_MAX_TITLE_LEN:
        return False, f"标题过长（最大 {FORUM_MAX_TITLE_LEN} 字符）"
    if not content or not content.strip():
        return False, "正文不能为空"
    if len(content) > FORUM_MAX_CONTENT_LEN:
        return False, f"正文过长（最大 {FORUM_MAX_CONTENT_LEN} 字符）"
    if tags and len(tags) > FORUM_MAX_TAGS_PER_POST:
        return False, f"标签过多（最多 {FORUM_MAX_TAGS_PER_POST} 个）"
    for tag in tags:
        if len(tag) > FORUM_MAX_TAG_LEN:
            return False, f"标签 '{tag}' 过长（最大 {FORUM_MAX_TAG_LEN} 字符）"
    return True, ""


def calculate_hot_score(net_votes: int, distinct_commenters: int,
                         post_timestamp: int, w: float = FORUM_DEFAULT_HOT_WEIGHT) -> float:
    """
    计算热度分。
    hot = log10(max(|net_votes|,1))*sign(net_votes) + w*log10(max(distinct_commenters,1)) + post_ts/45000
    """
    vote_part = math.log10(max(abs(net_votes), 1))
    if net_votes > 0:
        vote_part *= 1
    elif net_votes < 0:
        vote_part *= -1
    else:
        vote_part = 0  # sign(0)=0 显式处理

    comment_part = w * math.log10(max(distinct_commenters, 1))
    time_part = post_timestamp / 45000.0

    return vote_part + comment_part + time_part


def why_ranked(post_id: str) -> dict:
    """'为什么这个排名'分解。返回热度公式各组成部分。"""
    db = get_forum_db()
    row = db.execute(
        "SELECT net_votes, distinct_commenters, created_at, hot_score FROM posts WHERE id=?",
        (post_id,)
    ).fetchone()
    if not row:
        return {}
    net_votes = row["net_votes"]
    distinct = row["distinct_commenters"]
    ts = row["created_at"]

    vote_part = math.log10(max(abs(net_votes), 1))
    if net_votes > 0:
        vote_part *= 1
    elif net_votes < 0:
        vote_part *= -1
    else:
        vote_part = 0
    comment_part = FORUM_DEFAULT_HOT_WEIGHT * math.log10(max(distinct, 1))
    time_part = ts / 45000.0

    return {
        "post_id": post_id,
        "hot_score": row["hot_score"],
        "breakdown": {
            "vote_score": round(vote_part, 4),
            "vote_detail": f"log10(max(|{net_votes}|,1))*sign({net_votes}) = {round(vote_part, 4)}",
            "comment_score": round(comment_part, 4),
            "comment_detail": f"{FORUM_DEFAULT_HOT_WEIGHT}*log10(max({distinct},1)) = {round(comment_part, 4)}",
            "time_score": round(time_part, 4),
            "time_detail": f"{ts}/45000 = {round(time_part, 4)}",
        },
        "net_votes": net_votes,
        "distinct_commenters": distinct,
        "created_at": ts,
    }


def create_post(node_id: str, author_uuid: str, title: str, content: str,
                tags: list, author_signature: str, server_signature: str,
                author_pubkey: str) -> dict:
    """创建帖子。返回帖子字典。"""
    db = get_forum_db()
    post_id = generate_post_id(node_id)
    ts = now_ts()
    tags_str = ",".join(t.strip() for t in tags if t.strip())

    hot = calculate_hot_score(0, 0, ts)

    db.execute("""
        INSERT INTO posts (id, node_id, author_uuid, title, content, tags,
            author_signature, server_signature, author_pubkey, hot_score,
            created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (post_id, node_id, author_uuid, title.strip(), content, tags_str,
          author_signature, server_signature, author_pubkey, hot, ts, ts))
    db.commit()

    return get_post(post_id)


def get_post(post_id: str, include_deleted: bool = False) -> dict | None:
    """按 ID 获取帖子。"""
    db = get_forum_db()
    if include_deleted:
        row = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    else:
        row = db.execute("SELECT * FROM posts WHERE id=? AND deleted=0", (post_id,)).fetchone()
    return dict(row) if row else None


def list_posts(sort: str = "hot", limit: int = 20, offset: int = 0,
               tag: str = "", author_uuid: str = "") -> list:
    """
    获取帖子列表（游标分页）。
    sort: hot / new / top
    """
    db = get_forum_db()
    query = "SELECT * FROM posts WHERE deleted=0"
    params = []
    if tag:
        query += " AND tags LIKE ?"
        params.append(f"%{tag}%")
    if author_uuid:
        query += " AND author_uuid=?"
        params.append(author_uuid)

    if sort == "new":
        query += " ORDER BY created_at DESC"
    elif sort == "top":
        query += " ORDER BY net_votes DESC"
    else:  # hot
        query += " ORDER BY hot_score DESC"

    query += " LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = db.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def search_posts(query: str, limit: int = 20, offset: int = 0) -> list:
    """搜索帖子（本服，FTS5 全文搜索，空结果或不可用时降级为 LIKE）。"""
    db = get_forum_db()
    rows = []
    try:
        rows = db.execute("""
            SELECT p.* FROM posts p
            JOIN posts_fts f ON p.rowid = f.rowid
            WHERE posts_fts MATCH ? AND p.deleted=0
            ORDER BY p.hot_score DESC LIMIT ? OFFSET ?
        """, (query, limit, offset)).fetchall()
    except sqlite3.OperationalError:
        pass  # FTS5 不可用，降级

    # FTS5 外部内容表可能未索引，空结果时降级为 LIKE
    if not rows:
        like = f"%{query}%"
        rows = db.execute("""
            SELECT * FROM posts WHERE deleted=0
            AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)
            ORDER BY hot_score DESC LIMIT ? OFFSET ?
        """, (like, like, like, limit, offset)).fetchall()

    return [dict(r) for r in rows]


def edit_post(post_id: str, author_uuid: str, title: str, content: str,
              tags: list, author_signature: str, server_signature: str) -> dict | None:
    """编辑帖子（显示已编辑标记）。"""
    db = get_forum_db()
    ts = now_ts()
    tags_str = ",".join(t.strip() for t in tags if t.strip())

    db.execute("""
        UPDATE posts SET title=?, content=?, tags=?, author_signature=?,
        server_signature=?, edited=1, updated_at=?
        WHERE id=? AND author_uuid=? AND deleted=0
    """, (title.strip(), content, tags_str, author_signature, server_signature,
          ts, post_id, author_uuid))
    db.commit()
    return get_post(post_id)


def delete_post(post_id: str, deleted_by: str, is_admin: bool = False) -> bool:
    """删除帖子（墓碑，不级联评论）。作者或管理员可删。"""
    db = get_forum_db()
    post = get_post(post_id)
    if not post:
        return False
    if not is_admin and post["author_uuid"] != deleted_by:
        return False
    ts = now_ts()
    db.execute("""
        UPDATE posts SET deleted=1, deleted_by=?, deleted_at=?, updated_at=?
        WHERE id=?
    """, (deleted_by, ts, ts, post_id))
    db.commit()
    return True


def recalc_hot_scores(limit: int = 500):
    """后台批量重算热度分（每 5-10 分钟调用）。"""
    db = get_forum_db()
    rows = db.execute("""
        SELECT id, net_votes, distinct_commenters, created_at
        FROM posts WHERE deleted=0 ORDER BY hot_score DESC LIMIT ?
    """, (limit,)).fetchall()

    for row in rows:
        hot = calculate_hot_score(row["net_votes"], row["distinct_commenters"], row["created_at"])
        db.execute("UPDATE posts SET hot_score=? WHERE id=?", (hot, row["id"]))
    db.commit()
    return len(rows)


def update_post_stats(post_id: str):
    """更新帖子的评论数和去重评论者数。"""
    db = get_forum_db()
    result = db.execute("""
        SELECT COUNT(*) as cnt, COUNT(DISTINCT author_uuid) as distinct_authors
        FROM comments WHERE post_id=? AND deleted=0
    """, (post_id,)).fetchone()
    db.execute("""
        UPDATE posts SET comment_count=?, distinct_commenters=? WHERE id=?
    """, (result["cnt"], result["distinct_authors"], post_id))
    db.commit()


def get_post_count() -> int:
    db = get_forum_db()
    return db.execute("SELECT COUNT(*) as c FROM posts WHERE deleted=0").fetchone()["c"]

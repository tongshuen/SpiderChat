"""
评论管理 — 两层结构（根评论按热度，回复按时间）。
删除为墓碑不级联，编辑显示已编辑标记。
"""

import secrets
import sqlite3
from server.forum.database import get_forum_db, now_ts
from server.forum.posts import update_post_stats, get_post
from shared.protocol import FORUM_MAX_COMMENT_LEN, FORUM_POST_ID_HEX_LEN


def generate_comment_id(node_id: str) -> str:
    return f"{node_id}:{secrets.token_hex(FORUM_POST_ID_HEX_LEN // 2)}"


def create_comment(node_id: str, post_id: str, author_uuid: str, content: str,
                    parent_id: str, author_signature: str, server_signature: str,
                    author_pubkey: str) -> dict | None:
    """创建评论。"""
    if not content or not content.strip():
        return None
    if len(content) > FORUM_MAX_COMMENT_LEN:
        return None

    post = get_post(post_id)
    if not post:
        return None

    db = get_forum_db()
    comment_id = generate_comment_id(node_id)
    ts = now_ts()

    db.execute("""
        INSERT INTO comments (id, post_id, parent_id, author_uuid, content,
            author_signature, server_signature, author_pubkey, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (comment_id, post_id, parent_id or "", author_uuid, content,
          author_signature, server_signature, author_pubkey, ts, ts))
    db.commit()

    update_post_stats(post_id)
    return get_comment(comment_id)


def get_comment(comment_id: str) -> dict | None:
    db = get_forum_db()
    row = db.execute("SELECT * FROM comments WHERE id=?", (comment_id,)).fetchone()
    return dict(row) if row else None


def list_comments(post_id: str, sort: str = "hot") -> dict:
    """
    获取帖子评论（两层结构）。
    根评论按 hot_score(net_votes) 降序，回复按时间升序。
    返回 {"roots": [...], "replies": {parent_id: [...]}}
    """
    db = get_forum_db()
    roots = db.execute("""
        SELECT * FROM comments WHERE post_id=? AND parent_id='' AND deleted=0
        ORDER BY net_votes DESC, created_at ASC
    """, (post_id,)).fetchall()

    replies_map = {}
    for root in roots:
        replies = db.execute("""
            SELECT * FROM comments WHERE post_id=? AND parent_id=? AND deleted=0
            ORDER BY created_at ASC
        """, (post_id, root["id"])).fetchall()
        replies_map[root["id"]] = [dict(r) for r in replies]

    return {
        "roots": [dict(r) for r in roots],
        "replies": replies_map,
    }


def edit_comment(comment_id: str, author_uuid: str, content: str,
                 author_signature: str, server_signature: str) -> dict | None:
    db = get_forum_db()
    ts = now_ts()
    db.execute("""
        UPDATE comments SET content=?, author_signature=?, server_signature=?,
        edited=1, updated_at=? WHERE id=? AND author_uuid=? AND deleted=0
    """, (content, author_signature, server_signature, ts, comment_id, author_uuid))
    db.commit()
    return get_comment(comment_id)


def delete_comment(comment_id: str, deleted_by: str, is_admin: bool = False) -> bool:
    """删除评论（墓碑，不级联）。"""
    db = get_forum_db()
    comment = get_comment(comment_id)
    if not comment:
        return False
    if not is_admin and comment["author_uuid"] != deleted_by:
        return False
    ts = now_ts()
    db.execute("""
        UPDATE comments SET deleted=1, deleted_by=?, deleted_at=?, updated_at=?
        WHERE id=?
    """, (deleted_by, ts, ts, comment_id))
    db.commit()
    update_post_stats(comment["post_id"])
    return True

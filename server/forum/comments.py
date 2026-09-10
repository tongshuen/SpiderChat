"""
评论管理 — 树状本质 + 扁平热度排序。

存储层：comments.parent_id 支持任意深度的评论树（不限制两层）。
展示层：list_comments 一次性返回该帖子下所有未删除评论的扁平列表，
每条带 reply_to_username（父评论作者），前端按 tree 关系自行折叠。

热度排序公式（降序）：
    hot = net_votes + 2 * log10(reply_count + 1) - age_hours / 12
  - reply_count  该评论的直接回复数
  - age_hours    评论距今的小时数
  - net_votes 相同时按 created_at 升序（老评论在前，稳定排序）。

删除为墓碑不级联，编辑显示已编辑标记。
"""

import math
import os
import secrets
import sqlite3
import time
from server.forum.database import get_forum_db, now_ts
from server.forum.posts import update_post_stats, get_post
from shared.protocol import FORUM_MAX_COMMENT_LEN, FORUM_POST_ID_HEX_LEN


DELETED_USER_LABEL = "已删除用户"


def generate_comment_id(node_id: str) -> str:
    return f"{node_id}:{secrets.token_hex(FORUM_POST_ID_HEX_LEN // 2)}"


def _resolve_author_name(author_uuid: str) -> str:
    """
    将评论作者 UUID 解析为可显示的用户名。
    优先返回 users.db 中的 name；为空或查无此人时回退到 UUID。
    """
    if not author_uuid:
        return ""
    try:
        data_dir = os.environ.get("SPIDER_DATA_DIR")
        if not data_dir:
            from client.utils.config import get_data_dir
            data_dir = get_data_dir()
        users_db_path = os.path.join(data_dir, "users.db")
        if os.path.exists(users_db_path):
            conn = sqlite3.connect(users_db_path)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT name FROM users WHERE uuid=?", (author_uuid,)
            ).fetchone()
            conn.close()
            if row and row["name"]:
                return row["name"]
    except Exception:
        pass
    return author_uuid


def create_comment(node_id: str, post_id: str, author_uuid: str, content: str,
                   parent_id: str, author_signature: str, server_signature: str,
                   author_pubkey: str) -> dict | None:
    """
    创建评论。支持任意深度回复。

    若 parent_id 非空，必须校验该父评论存在且属于同一 post_id，否则拒绝创建。
    """
    if not content or not content.strip():
        return None
    if len(content) > FORUM_MAX_COMMENT_LEN:
        return None

    post = get_post(post_id)
    if not post:
        return None

    # 校验父评论：非空时必须存在且与本评论属于同一帖子
    if parent_id:
        db = get_forum_db()
        parent = db.execute(
            "SELECT id, post_id, deleted FROM comments WHERE id=?", (parent_id,)
        ).fetchone()
        if not parent:
            # 父评论不存在，拒绝悬挂回复
            return None
        if parent["post_id"] != post_id:
            # 跨帖子回复，拒绝
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


def _comment_hot(net_votes: int, reply_count: int, created_at: int) -> float:
    """热度公式：net_votes + 2*log10(reply_count+1) - age_hours/12。"""
    age_hours = max((time.time() - created_at) / 3600.0, 0.0)
    return net_votes + 2.0 * math.log10(reply_count + 1) - age_hours / 12.0


def list_comments(post_id: str, sort: str = "hot") -> dict:
    """
    获取帖子下所有未删除评论（任意深度），返回扁平列表 {"comments": [...]}。

    每条评论额外包含：
      - reply_to_username: 父评论作者的用户名/UUID；父评论已删除或不存在时为
        "已删除用户"；根评论为空串。
      - reply_count: 该评论的直接回复数。
      - hot_score: 本次计算的热度分。

    排序：热度降序；net_votes 相同时按 created_at 升序（稳定）。
    """
    db = get_forum_db()

    # 取该帖子所有未删除评论
    rows = db.execute("""
        SELECT * FROM comments WHERE post_id=? AND deleted=0
    """, (post_id,)).fetchall()

    comments = [dict(r) for r in rows]

    # 统计每条评论的直接回复数（直接子评论，未删除）
    reply_count_map: dict[str, int] = {}
    for c in comments:
        parent = c["parent_id"] or ""
        if parent:
            reply_count_map[parent] = reply_count_map.get(parent, 0) + 1

    # 也需要纳入"父评论已被删除"的情况：父评论不在未删除集合中。
    # 查询该帖子所有（含已删除）评论的 author 映射，用于 reply_to 解析。
    all_rows = db.execute(
        "SELECT id, author_uuid, deleted FROM comments WHERE post_id=?", (post_id,)
    ).fetchall()
    deleted_ids = set()
    author_by_parent: dict[str, str] = {}
    for r in all_rows:
        author_by_parent[r["id"]] = r["author_uuid"]
        if r["deleted"]:
            deleted_ids.add(r["id"])

    # 组装扁平列表
    result = []
    for c in comments:
        parent_id = c["parent_id"] or ""
        if not parent_id:
            reply_to_username = ""
        else:
            if parent_id in deleted_ids or parent_id not in author_by_parent:
                reply_to_username = DELETED_USER_LABEL
            else:
                reply_to_username = _resolve_author_name(author_by_parent[parent_id])

        rc = reply_count_map.get(c["id"], 0)
        c["reply_to_username"] = reply_to_username
        c["reply_count"] = rc
        c["hot_score"] = _comment_hot(c["net_votes"], rc, c["created_at"])
        result.append(c)

    # 排序：热度降序；net_votes 相同时按 created_at 升序
    result.sort(key=lambda x: (-x["hot_score"], x["created_at"]))

    return {"comments": result}


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

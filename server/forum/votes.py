"""
投票管理 — 每用户每对象一票，改票正确回滚旧票。
投票值 -1/0/1，新用户 24 小时内投票不计入热度。
乐观更新失败回滚。
"""

import time
from server.forum.database import get_forum_db, now_ts
from server.forum.posts import calculate_hot_score
from shared.protocol import FORUM_NEW_USER_COOLDOWN_HOURS


def _get_user_register_time(user_uuid: str) -> int:
    """获取用户注册时间（从 users.db 查，降级返回 0 表示老用户）。"""
    try:
        import os
        import sqlite3
        data_dir = os.environ.get("SPIDER_DATA_DIR")
        if not data_dir:
            from client.utils.config import get_data_dir
            data_dir = get_data_dir()
        users_db_path = os.path.join(data_dir, "users.db")
        if os.path.exists(users_db_path):
            conn = sqlite3.connect(users_db_path)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT created_at FROM users WHERE uuid=?", (user_uuid,)
            ).fetchone()
            conn.close()
            if row:
                return row["created_at"]
    except Exception:
        pass
    return 0


def is_new_user(user_uuid: str) -> bool:
    """判断是否新用户（注册 24 小时内）。"""
    reg_time = _get_user_register_time(user_uuid)
    if reg_time == 0:
        return False
    return (now_ts() - reg_time) < FORUM_NEW_USER_COOLDOWN_HOURS * 3600


def cast_vote(user_uuid: str, target_type: str, target_id: str, value: int) -> dict:
    """
    投票。value: -1/0/1。
    返回 {"success": bool, "new_value": int, "net_votes": int, "hot_score": float, "counted": bool}
    counted=False 表示新用户投票不计入热度。
    """
    if value not in (-1, 0, 1):
        return {"success": False, "error": "投票值必须为 -1/0/1"}

    db = get_forum_db()
    ts = now_ts()
    counted = not is_new_user(user_uuid)

    # 查找旧票
    old = db.execute(
        "SELECT * FROM votes WHERE user_uuid=? AND target_type=? AND target_id=?",
        (user_uuid, target_type, target_id)
    ).fetchone()

    try:
        if old:
            old_value = old["value"]
            if old_value == value:
                # 相同值，取消投票（设为0）
                db.execute(
                    "UPDATE votes SET value=0, updated_at=? WHERE id=?",
                    (ts, old["id"])
                )
                new_value = 0
            else:
                db.execute(
                    "UPDATE votes SET value=?, updated_at=? WHERE id=?",
                    (value, ts, old["id"])
                )
                new_value = value
            # 回滚旧票的影响
            delta = new_value - old_value
        else:
            if value == 0:
                return {"success": True, "new_value": 0, "net_votes": 0, "hot_score": 0, "counted": counted}
            db.execute("""
                INSERT INTO votes (user_uuid, target_type, target_id, value, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_uuid, target_type, target_id, value, ts, ts))
            delta = value
            new_value = value

        # 更新目标的净投票数（仅 counted 时计入热度）
        if target_type == "post":
            row = db.execute("SELECT net_votes, distinct_commenters, created_at FROM posts WHERE id=?",
                             (target_id,)).fetchone()
            if row:
                new_net = row["net_votes"] + (delta if counted else 0)
                hot = calculate_hot_score(new_net, row["distinct_commenters"], row["created_at"])
                db.execute("UPDATE posts SET net_votes=?, hot_score=? WHERE id=?",
                          (new_net, hot, target_id))
                # 更新 up/down 计数
                if delta > 0:
                    db.execute("UPDATE posts SET upvotes=upvotes+1 WHERE id=?", (target_id,))
                elif delta < 0:
                    db.execute("UPDATE posts SET downvotes=downvotes+1 WHERE id=?", (target_id,))
        elif target_type == "comment":
            db.execute("UPDATE comments SET net_votes=net_votes+? WHERE id=?",
                      (delta if counted else 0, target_id))

        db.commit()

        # 返回最新状态（目标不存在时返回默认值）
        if target_type == "post":
            row = db.execute("SELECT net_votes, hot_score FROM posts WHERE id=?", (target_id,)).fetchone()
            net_votes = row["net_votes"] if row else 0
            hot_score = row["hot_score"] if row else 0
            return {"success": True, "new_value": new_value, "net_votes": net_votes,
                    "hot_score": hot_score, "counted": counted}
        else:
            row = db.execute("SELECT net_votes FROM comments WHERE id=?", (target_id,)).fetchone()
            net_votes = row["net_votes"] if row else 0
            return {"success": True, "new_value": new_value, "net_votes": net_votes,
                    "hot_score": 0, "counted": counted}

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}


def get_user_vote(user_uuid: str, target_type: str, target_id: str) -> int:
    """获取用户对某对象的投票值。"""
    db = get_forum_db()
    row = db.execute(
        "SELECT value FROM votes WHERE user_uuid=? AND target_type=? AND target_id=?",
        (user_uuid, target_type, target_id)
    ).fetchone()
    return row["value"] if row else 0

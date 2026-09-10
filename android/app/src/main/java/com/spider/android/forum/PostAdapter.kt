package com.spider.android.forum

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.spider.android.R
import org.json.JSONObject

/**
 * 帖子列表适配器。
 *
 * 同时提供评论扁平视图构建方法 [buildCommentView]：
 * 评论按服务端返回顺序扁平显示，不做缩进分层；
 * 若 parent_id 非空，在评论头部显示"回复 @用户名"（使用 reply_to_username 字段）。
 */
class PostAdapter(
    private val posts: MutableList<JSONObject>,
    private val onPostClick: (JSONObject) -> Unit
) : RecyclerView.Adapter<PostAdapter.PostViewHolder>() {

    class PostViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView = view.findViewById(R.id.postTitle)
        val meta: TextView = view.findViewById(R.id.postMeta)
        val tags: TextView = view.findViewById(R.id.postTags)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PostViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_post, parent, false)
        return PostViewHolder(view)
    }

    override fun onBindViewHolder(holder: PostViewHolder, position: Int) {
        val post = posts[position]
        holder.title.text = post.optString("title", "")
        val up = post.optInt("upvotes", 0)
        val down = post.optInt("downvotes", 0)
        val comments = post.optInt("comment_count", 0)
        holder.meta.text = "↑$up ↓$down | 💬$comments"
        val tags = post.optString("tags", "")
        holder.tags.text = if (tags.isNotEmpty()) "#${tags.replace(",", " #")}" else ""
        holder.itemView.setOnClickListener { onPostClick(post) }
    }

    override fun getItemCount() = posts.size

    fun updatePosts(newPosts: List<JSONObject>) {
        posts.clear()
        posts.addAll(newPosts)
        notifyDataSetChanged()
    }

    companion object {
        /**
         * 构建一条扁平评论视图。
         *
         * 新 API 评论字段：id, parent_id, reply_to_username, content,
         * author_uuid, net_votes, created_at。
         *
         * 不做缩进分层；若 parent_id 非空，头部显示"回复 @reply_to_username"。
         */
        @JvmStatic
        fun buildCommentView(context: Context, comment: JSONObject): View {
            val container = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(20, 10, 20, 10)
            }

            val author = comment.optString("author_uuid", "").take(10)
            val parentId = comment.optString("parent_id", "")
            val replyToUser = comment.optString("reply_to_username", "")

            // 头部：作者 + 可选"回复 @用户名"
            val header = StringBuilder(author)
            if (parentId.isNotEmpty() && replyToUser.isNotEmpty()) {
                header.append("  回复 @").append(replyToUser)
            }
            val headerView = TextView(context).apply {
                text = header.toString()
                textSize = 11f
                setTextColor(0xFF888888.toInt())
            }
            container.addView(headerView)

            // 正文
            val contentView = TextView(context).apply {
                text = comment.optString("content", "")
                textSize = 13f
                setTextColor(0xFFEEEEEE.toInt())
            }
            container.addView(contentView)

            return container
        }
    }
}

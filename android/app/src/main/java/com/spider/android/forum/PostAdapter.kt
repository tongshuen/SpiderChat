package com.spider.android.forum

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.spider.android.R
import org.json.JSONObject

/**
 * 帖子列表适配器。
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
}

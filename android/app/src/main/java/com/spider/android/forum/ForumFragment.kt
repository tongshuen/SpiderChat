package com.spider.android.forum

import android.app.AlertDialog
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.spider.android.R
import com.spider.android.SpiderApp
import org.json.JSONArray
import org.json.JSONObject

/**
 * 论坛主 Fragment — 帖子列表、帖子详情、发帖、评论、投票。
 *
 * 发帖页顶部醒目警示：帖子评论明文存储，管理员可查看删除导出，
 * 等同于公开发布，不可否认，敏感信息请移步私聊。
 */
class ForumFragment : Fragment() {

    private val TAG = "ForumFragment"
    private val app by lazy { requireActivity().application as SpiderApp }

    private lateinit var postRecyclerView: RecyclerView
    private lateinit var postAdapter: PostAdapter
    private lateinit var searchBox: EditText
    private lateinit var sortSpinner: Spinner
    private lateinit var createBtn: Button
    private lateinit var detailContainer: LinearLayout
    private lateinit var listContainer: LinearLayout
    private lateinit var backBtn: Button
    private lateinit var detailTitle: TextView
    private lateinit var detailContent: TextView
    private lateinit var detailMeta: TextView
    private lateinit var upvoteBtn: Button
    private lateinit var downvoteBtn: Button
    private lateinit var commentInput: EditText
    private lateinit var commentSendBtn: Button
    private lateinit var commentList: LinearLayout

    private val posts = mutableListOf<JSONObject>()
    private var currentPost: JSONObject? = null
    private var currentSort = "hot"
    private var searchMode = false

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_forum, container, false)

        listContainer = view.findViewById(R.id.listContainer)
        detailContainer = view.findViewById(R.id.detailContainer)
        postRecyclerView = view.findViewById(R.id.postRecyclerView)
        searchBox = view.findViewById(R.id.forumSearch)
        sortSpinner = view.findViewById(R.id.sortSpinner)
        createBtn = view.findViewById(R.id.createPostBtn)
        backBtn = view.findViewById(R.id.backBtn)
        detailTitle = view.findViewById(R.id.detailTitle)
        detailContent = view.findViewById(R.id.detailContent)
        detailMeta = view.findViewById(R.id.detailMeta)
        upvoteBtn = view.findViewById(R.id.upvoteBtn)
        downvoteBtn = view.findViewById(R.id.downvoteBtn)
        commentInput = view.findViewById(R.id.commentInput)
        commentSendBtn = view.findViewById(R.id.commentSendBtn)
        commentList = view.findViewById(R.id.commentList)

        // 帖子列表
        postAdapter = PostAdapter(posts) { post -> openPostDetail(post) }
        postRecyclerView.layoutManager = LinearLayoutManager(requireContext())
        postRecyclerView.adapter = postAdapter

        // 排序
        val sorts = arrayOf("热度", "最新", "最高")
        sortSpinner.adapter = ArrayAdapter(requireContext(), android.R.layout.simple_spinner_dropdown_item, sorts)
        sortSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                currentSort = when (position) { 0 -> "hot"; 1 -> "new"; else -> "top" }
                searchMode = false
                loadPosts()
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // 搜索
        searchBox.setOnEditorActionListener { _, _, _ ->
            val q = searchBox.text.toString().trim()
            if (q.isNotEmpty()) {
                searchMode = true
                searchPosts(q)
            } else {
                searchMode = false
                loadPosts()
            }
            true
        }

        // 发帖
        createBtn.setOnClickListener { showCreatePostDialog() }

        // 返回
        backBtn.setOnClickListener { backToList() }

        // 投票
        upvoteBtn.setOnClickListener { vote(1) }
        downvoteBtn.setOnClickListener { vote(-1) }

        // 评论
        commentSendBtn.setOnClickListener { submitComment() }

        // 加载帖子
        loadPosts()

        return view
    }

    // ===== 网络操作 =====

    private fun sendForumMessage(msg: JSONObject) {
        app.spiderClient?.send(msg)
    }

    private fun loadPosts() {
        val req = JSONObject().apply {
            put("type", "POST_LIST")
            put("sort", currentSort)
            put("limit", 50)
        }
        sendForumMessage(req)
    }

    private fun searchPosts(query: String) {
        val req = JSONObject().apply {
            put("type", "POST_SEARCH")
            put("query", query)
            put("limit", 50)
        }
        sendForumMessage(req)
    }

    private fun openPostDetail(post: JSONObject) {
        currentPost = post
        listContainer.visibility = View.GONE
        detailContainer.visibility = View.VISIBLE
        renderPostDetail(post)

        // 请求完整帖子和评论
        val req = JSONObject().apply {
            put("type", "POST_GET")
            put("id", post.optString("id"))
        }
        sendForumMessage(req)

        val cReq = JSONObject().apply {
            put("type", "COMMENT_LIST")
            put("post_id", post.optString("id"))
        }
        sendForumMessage(cReq)
    }

    private fun backToList() {
        currentPost = null
        detailContainer.visibility = View.GONE
        listContainer.visibility = View.VISIBLE
    }

    private fun vote(value: Int) {
        val post = currentPost ?: return
        val req = JSONObject().apply {
            put("type", "VOTE_CAST")
            put("target_type", "post")
            put("target_id", post.optString("id"))
            put("value", value)
        }
        sendForumMessage(req)
    }

    private fun submitComment() {
        val post = currentPost ?: return
        val content = commentInput.text.toString().trim()
        if (content.isEmpty()) return

        val req = JSONObject().apply {
            put("type", "COMMENT_CREATE")
            put("post_id", post.optString("id"))
            put("content", content)
        }
        sendForumMessage(req)
        commentInput.setText("")
    }

    // ===== UI 渲染 =====

    private fun renderPostDetail(post: JSONObject) {
        detailTitle.text = post.optString("title", "")
        detailContent.text = post.optString("content", "")
        val author = post.optString("author_uuid", "").take(12) + "..."
        val net = post.optInt("net_votes", 0)
        val up = post.optInt("upvotes", 0)
        val down = post.optInt("downvotes", 0)
        detailMeta.text = "作者: $author | 净投票: $net (↑$up ↓$down)"
        upvoteBtn.text = "👍 $up"
        downvoteBtn.text = "👎 $down"
    }

    private fun renderComments(roots: JSONArray, replies: JSONObject) {
        commentList.removeAllViews()
        for (i in 0 until roots.length()) {
            val root = roots.getJSONObject(i)
            commentList.addView(createCommentView(root, 0))
            val replyArr = replies.optJSONArray(root.optString("id"))
            if (replyArr != null) {
                for (j in 0 until replyArr.length()) {
                    commentList.addView(createCommentView(replyArr.getJSONObject(j), 1))
                }
            }
        }
    }

    private fun createCommentView(comment: JSONObject, depth: Int): View {
        val tv = TextView(requireContext()).apply {
            val author = comment.optString("author_uuid", "").take(10)
            text = "${if (depth > 0) "  └ " else ""}$author: ${comment.optString("content", "")}"
            textSize = 13f
            setPadding(20 + depth * 30, 8, 20, 8)
        }
        return tv
    }

    // ===== 发帖对话框 =====

    private fun showCreatePostDialog() {
        val dialogView = LayoutInflater.from(requireContext()).inflate(R.layout.dialog_create_post, null)
        val titleInput = dialogView.findViewById<EditText>(R.id.postTitleInput)
        val tagsInput = dialogView.findViewById<EditText>(R.id.postTagsInput)
        val contentInput = dialogView.findViewById<EditText>(R.id.postContentInput)
        val warningText = dialogView.findViewById<TextView>(R.id.warningText)

        warningText.text = "⚠ 重要警示：帖子和评论以明文存储在服务器上，管理员可查看、删除、导出。这等同于公开发布，不可否认。敏感信息请移步端到端加密私聊。"

        AlertDialog.Builder(requireContext())
            .setTitle("发布新帖")
            .setView(dialogView)
            .setPositiveButton("发布") { _, _ ->
                val title = titleInput.text.toString().trim()
                val content = contentInput.text.toString().trim()
                if (title.isEmpty() || content.isEmpty()) {
                    Toast.makeText(requireContext(), "标题和正文不能为空", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                val tags = JSONArray()
                tagsInput.text.toString().split(",").forEach { if (it.trim().isNotEmpty()) tags.put(it.trim()) }

                val req = JSONObject().apply {
                    put("type", "POST_CREATE")
                    put("title", title)
                    put("content", content)
                    put("tags", tags)
                }
                sendForumMessage(req)
            }
            .setNegativeButton("取消", null)
            .show()
    }

    // ===== 消息处理（由 MainActivity 调用） =====

    fun handleForumMessage(msg: JSONObject) {
        when (msg.optString("type", "")) {
            "POST_LIST_RESULT", "POST_SEARCH_RESULT", "POST_HOT_RANKING_RESULT" -> {
                val arr = msg.optJSONArray("posts") ?: JSONArray()
                val list = mutableListOf<JSONObject>()
                for (i in 0 until arr.length()) list.add(arr.getJSONObject(i))
                postAdapter.updatePosts(list)
            }
            "POST_GET_RESULT" -> {
                val post = msg.optJSONObject("post")
                if (post != null) {
                    currentPost = post
                    renderPostDetail(post)
                }
            }
            "COMMENT_LIST_RESULT" -> {
                val roots = msg.optJSONArray("roots") ?: JSONArray()
                val replies = msg.optJSONObject("replies") ?: JSONObject()
                renderComments(roots, replies)
            }
            "POST_CREATE_RESULT" -> {
                loadPosts()
                Toast.makeText(requireContext(), "帖子发布成功", Toast.LENGTH_SHORT).show()
            }
            "VOTE_CAST_RESULT" -> {
                currentPost?.let {
                    val req = JSONObject().apply {
                        put("type", "POST_GET")
                        put("id", it.optString("id"))
                    }
                    sendForumMessage(req)
                }
            }
            "ERROR" -> {
                Toast.makeText(requireContext(), msg.optString("message", "错误"), Toast.LENGTH_SHORT).show()
            }
        }
    }
}

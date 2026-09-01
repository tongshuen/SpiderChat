package com.spider.android.ui.main

import android.app.AlertDialog
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.spider.android.R
import com.spider.android.location.LocationHelper
import com.spider.android.model.Message

/**
 * 消息列表适配器 — 支持发送/接收两种布局。
 * 长按消息气泡可显示位置详情（如果消息中包含经纬度信息）。
 */
class MessageAdapter(
    private val messages: MutableList<Message>,
    private val myUuid: String
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    companion object {
        private const val TYPE_SENT = 0
        private const val TYPE_RECEIVED = 1
    }

    inner class SentViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvText: TextView = view.findViewById(R.id.tvText)
        val tvTime: TextView = view.findViewById(R.id.tvTime)
        val messageBubble: View = view.findViewById(R.id.messageBubble)
    }

    inner class ReceivedViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvText: TextView = view.findViewById(R.id.tvText)
        val tvTime: TextView = view.findViewById(R.id.tvTime)
        val messageBubble: View = view.findViewById(R.id.messageBubble)
    }

    override fun getItemViewType(position: Int): Int {
        return if (messages[position].fromUuid == myUuid) TYPE_SENT else TYPE_RECEIVED
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        return if (viewType == TYPE_SENT) {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_message_sent, parent, false)
            SentViewHolder(view)
        } else {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_message_received, parent, false)
            ReceivedViewHolder(view)
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val message = messages[position]
        val displayText = LocationHelper.stripMetadata(message.text)
        when (holder) {
            is SentViewHolder -> {
                holder.tvText.text = displayText
                holder.tvTime.text = message.timeString
                setupLongClick(holder.messageBubble, message)
            }
            is ReceivedViewHolder -> {
                holder.tvText.text = displayText
                holder.tvTime.text = message.timeString
                setupLongClick(holder.messageBubble, message)
            }
        }
    }

    /**
     * 设置长按监听器：如果消息中包含元数据（时间戳+位置），长按弹出详情。
     */
    private fun setupLongClick(view: View, message: Message) {
        view.setOnLongClickListener {
            val meta = LocationHelper.parseMetadata(message.text)
            if (meta != null && meta.first != null) {
                val (location, sendTs) = meta
                AlertDialog.Builder(view.context)
                    .setTitle("消息详情")
                    .setMessage(location!!.toDetailString(sendTs ?: location.timestamp))
                    .setPositiveButton("关闭", null)
                    .show()
                true
            } else {
                val sendTime = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault())
                    .format(java.util.Date((message.timestamp ?: System.currentTimeMillis() / 1000) * 1000))
                AlertDialog.Builder(view.context)
                    .setTitle("消息详情")
                    .setMessage("发送时间：$sendTime")
                    .setPositiveButton("关闭", null)
                    .show()
                true
            }
        }
    }

    override fun getItemCount(): Int = messages.size

    fun addMessage(message: Message) {
        messages.add(message)
        notifyItemInserted(messages.size - 1)
    }

    fun setMessages(newMessages: List<Message>) {
        messages.clear()
        messages.addAll(newMessages)
        notifyDataSetChanged()
    }
}

package com.spider.android.ui.main

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.spider.android.R
import com.spider.android.SpiderApp
import com.spider.android.model.Contact
import com.spider.android.model.Message

/**
 * 聊天片段 — 显示消息列表和输入框。
 */
class ChatFragment : Fragment() {

    private val app by lazy { requireActivity().application as SpiderApp }
    private val mainActivity by lazy { requireActivity() as MainActivity }

    private lateinit var rvMessages: RecyclerView
    private lateinit var etMessage: EditText
    private lateinit var btnSend: ImageButton
    private lateinit var btnFile: ImageButton
    private lateinit var tvEmpty: TextView

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                val contact = mainActivity.currentContact
                if (contact != null) {
                    mainActivity.sendFile(uri)
                } else {
                    Toast.makeText(requireContext(), "请先选择联系人", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private lateinit var messageAdapter: MessageAdapter
    private val messages = mutableListOf<Message>()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_chat, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        rvMessages = view.findViewById(R.id.rvMessages)
        etMessage = view.findViewById(R.id.etMessage)
        btnSend = view.findViewById(R.id.btnSend)
        btnFile = view.findViewById(R.id.btnFile)
        tvEmpty = view.findViewById(R.id.tvEmpty)

        val myUuid = app.keyManager.getUuid()
        messageAdapter = MessageAdapter(messages, myUuid)
        rvMessages.adapter = messageAdapter
        rvMessages.layoutManager = LinearLayoutManager(requireContext()).apply {
            stackFromEnd = true
        }

        btnSend.setOnClickListener {
            val text = etMessage.text.toString().trim()
            if (text.isNotEmpty()) {
                if (mainActivity.currentContact != null) {
                    mainActivity.sendMessage(text)
                    etMessage.text.clear()
                } else {
                    Toast.makeText(requireContext(), "请先选择联系人", Toast.LENGTH_SHORT).show()
                }
            }
        }

        btnFile.setOnClickListener {
            if (mainActivity.currentContact == null) {
                Toast.makeText(requireContext(), "请先选择联系人", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                type = "*/*"
                addCategory(Intent.CATEGORY_OPENABLE)
            }
            filePickerLauncher.launch(Intent.createChooser(intent, "选择文件"))
        }

        updateEmptyView()
    }

    fun onContactSelected(contact: Contact) {
        val myUuid = app.keyManager.getUuid()
        val history = app.messageStore.getMessagesWith(contact.uuid, myUuid)
        messages.clear()
        messages.addAll(history)
        messageAdapter.notifyDataSetChanged()
        updateEmptyView()
        if (messages.isNotEmpty()) {
            rvMessages.scrollToPosition(messages.size - 1)
        }
    }

    fun addMessage(message: Message) {
        if (isAdded) {
            messageAdapter.addMessage(message)
            rvMessages.scrollToPosition(messages.size - 1)
            updateEmptyView()
        }
    }

    /**
     * 全量刷新消息列表（用于 SEND_OK、送达回执等状态更新后）。
     */
    fun refreshMessages(newMessages: List<Message>) {
        if (isAdded) {
            messages.clear()
            messages.addAll(newMessages)
            messageAdapter.notifyDataSetChanged()
            if (messages.isNotEmpty()) {
                rvMessages.scrollToPosition(messages.size - 1)
            }
            updateEmptyView()
        }
    }

    private fun updateEmptyView() {
        if (mainActivity.currentContact == null) {
            tvEmpty.text = "请从联系人列表选择一个联系人开始聊天"
            tvEmpty.visibility = View.VISIBLE
            rvMessages.visibility = View.GONE
        } else if (messages.isEmpty()) {
            tvEmpty.text = getString(R.string.no_messages)
            tvEmpty.visibility = View.VISIBLE
            rvMessages.visibility = View.GONE
        } else {
            tvEmpty.visibility = View.GONE
            rvMessages.visibility = View.VISIBLE
        }
    }
}

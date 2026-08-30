package com.spider.android.ui.main

import android.app.AlertDialog
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.spider.android.R
import com.spider.android.SpiderApp
import com.spider.android.model.Contact

/**
 * 联系人片段 — 显示联系人列表，支持搜索和添加。
 */
class ContactsFragment : Fragment() {

    private val app by lazy { requireActivity().application as SpiderApp }
    private val mainActivity by lazy { requireActivity() as MainActivity }

    private lateinit var rvContacts: RecyclerView
    private lateinit var etSearch: EditText
    private lateinit var btnAdd: ImageButton
    private lateinit var tvEmpty: TextView

    private lateinit var contactAdapter: ContactAdapter
    private val contacts = mutableListOf<Contact>()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_contacts, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        rvContacts = view.findViewById(R.id.rvContacts)
        etSearch = view.findViewById(R.id.etSearch)
        btnAdd = view.findViewById(R.id.btnAddContact)
        tvEmpty = view.findViewById(R.id.tvEmpty)

        contactAdapter = ContactAdapter(contacts) { contact ->
            mainActivity.selectContact(contact)
        }
        rvContacts.adapter = contactAdapter
        rvContacts.layoutManager = LinearLayoutManager(requireContext())

        btnAdd.setOnClickListener { showAddContactDialog() }

        etSearch.setOnEditorActionListener { _, _, _ ->
            val query = etSearch.text.toString().trim()
            if (query.isNotEmpty()) {
                searchContacts(query)
            } else {
                refreshContacts()
            }
            true
        }

        refreshContacts()
    }

    override fun onResume() {
        super.onResume()
        refreshContacts()
    }

    fun refreshContacts() {
        if (isAdded) {
            val all = app.contactStore.getAllContacts()
            contacts.clear()
            contacts.addAll(all)
            contactAdapter.notifyDataSetChanged()
            updateEmptyView()
        }
    }

    private fun searchContacts(query: String) {
        // 先搜索本地
        val localResults = app.contactStore.searchContacts(query)
        if (localResults.isNotEmpty()) {
            contacts.clear()
            contacts.addAll(localResults)
            contactAdapter.notifyDataSetChanged()
            updateEmptyView()
        }
        // 同时搜索服务器
        app.spiderClient.searchContacts(query, "server")
    }

    private fun showAddContactDialog() {
        val input = EditText(requireContext()).apply {
            hint = getString(R.string.enter_uuid)
            setPadding(32, 24, 32, 24)
        }
        AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.add_contact))
            .setView(input)
            .setPositiveButton(getString(R.string.save)) { _, _ ->
                val uuid = input.text.toString().trim()
                if (uuid.isNotEmpty()) {
                    addContact(uuid)
                }
            }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    private fun addContact(uuid: String) {
        if (app.contactStore.getContactByUuid(uuid) != null) {
            android.widget.Toast.makeText(requireContext(), "联系人已存在", android.widget.Toast.LENGTH_SHORT).show()
            return
        }
        val contact = Contact(
            uuid = uuid,
            displayName = uuid.take(8)
        )
        app.contactStore.addContact(contact)
        contactAdapter.addContact(contact)
        updateEmptyView()
        // 查询公钥
        app.spiderClient.queryPubkey(uuid)
        android.widget.Toast.makeText(requireContext(), "联系人已添加", android.widget.Toast.LENGTH_SHORT).show()
    }

    private fun updateEmptyView() {
        if (contacts.isEmpty()) {
            tvEmpty.visibility = View.VISIBLE
            rvContacts.visibility = View.GONE
        } else {
            tvEmpty.visibility = View.GONE
            rvContacts.visibility = View.VISIBLE
        }
    }
}

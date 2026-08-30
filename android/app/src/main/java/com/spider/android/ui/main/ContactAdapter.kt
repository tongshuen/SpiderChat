package com.spider.android.ui.main

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.spider.android.R
import com.spider.android.model.Contact

/**
 * 联系人列表适配器。
 */
class ContactAdapter(
    private val contacts: MutableList<Contact>,
    private val onContactClick: (Contact) -> Unit
) : RecyclerView.Adapter<ContactAdapter.ContactViewHolder>() {

    inner class ContactViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvName: TextView = view.findViewById(R.id.tvName)
        val tvUuid: TextView = view.findViewById(R.id.tvUuid)
        val tvOnline: TextView = view.findViewById(R.id.tvOnline)

        init {
            view.setOnClickListener {
                val position = adapterPosition
                if (position != RecyclerView.NO_POSITION) {
                    onContactClick(contacts[position])
                }
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ContactViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_contact, parent, false)
        return ContactViewHolder(view)
    }

    override fun onBindViewHolder(holder: ContactViewHolder, position: Int) {
        val contact = contacts[position]
        holder.tvName.text = contact.displayName.ifEmpty { contact.shortUuid }
        holder.tvUuid.text = contact.shortUuid
        holder.tvOnline.visibility = if (contact.isOnline) View.VISIBLE else View.GONE
    }

    override fun getItemCount(): Int = contacts.size

    fun setContacts(newContacts: List<Contact>) {
        contacts.clear()
        contacts.addAll(newContacts)
        notifyDataSetChanged()
    }

    fun addContact(contact: Contact) {
        val existing = contacts.indexOfFirst { it.uuid == contact.uuid }
        if (existing >= 0) {
            contacts[existing] = contact
            notifyItemChanged(existing)
        } else {
            contacts.add(contact)
            notifyItemInserted(contacts.size - 1)
        }
    }
}

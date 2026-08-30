package com.spider.android.storage

import android.content.ContentValues
import android.content.Context
import com.spider.android.model.Contact

/**
 * 联系人存储 — SQLite CRUD。
 */
class ContactStore(context: Context) {

    private val dbHelper = DatabaseHelper(context)

    fun addContact(contact: Contact): Long {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("uuid", contact.uuid)
            put("display_name", contact.displayName)
            put("x25519_pub", contact.x25519Pub)
            put("ed25519_pub", contact.ed25519Pub)
            put("is_online", if (contact.isOnline) 1 else 0)
            put("last_seen", contact.lastSeen)
            put("added_at", contact.addedAt)
        }
        return db.insertWithOnConflict(
            DatabaseHelper.TABLE_CONTACTS, null, values,
            android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE
        )
    }

    fun getAllContacts(): List<Contact> {
        val db = dbHelper.readableDatabase
        val contacts = mutableListOf<Contact>()
        val cursor = db.query(
            DatabaseHelper.TABLE_CONTACTS, null, null, null,
            null, null, "display_name ASC"
        )
        cursor.use {
            while (it.moveToNext()) {
                contacts.add(cursorToContact(it))
            }
        }
        return contacts
    }

    fun getContactByUuid(uuid: String): Contact? {
        val db = dbHelper.readableDatabase
        val cursor = db.query(
            DatabaseHelper.TABLE_CONTACTS, null, "uuid = ?",
            arrayOf(uuid), null, null, null
        )
        cursor.use {
            if (it.moveToFirst()) {
                return cursorToContact(it)
            }
        }
        return null
    }

    fun updateContactPubkeys(uuid: String, x25519Pub: String, ed25519Pub: String) {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("x25519_pub", x25519Pub)
            put("ed25519_pub", ed25519Pub)
        }
        db.update(DatabaseHelper.TABLE_CONTACTS, values, "uuid = ?", arrayOf(uuid))
    }

    fun updateOnlineStatus(uuid: String, isOnline: Boolean) {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("is_online", if (isOnline) 1 else 0)
            put("last_seen", System.currentTimeMillis() / 1000)
        }
        db.update(DatabaseHelper.TABLE_CONTACTS, values, "uuid = ?", arrayOf(uuid))
    }

    fun deleteContact(uuid: String) {
        val db = dbHelper.writableDatabase
        db.delete(DatabaseHelper.TABLE_CONTACTS, "uuid = ?", arrayOf(uuid))
    }

    fun searchContacts(query: String): List<Contact> {
        val db = dbHelper.readableDatabase
        val contacts = mutableListOf<Contact>()
        val cursor = db.query(
            DatabaseHelper.TABLE_CONTACTS, null,
            "display_name LIKE ? OR uuid LIKE ?",
            arrayOf("%$query%", "%$query%"),
            null, null, "display_name ASC"
        )
        cursor.use {
            while (it.moveToNext()) {
                contacts.add(cursorToContact(it))
            }
        }
        return contacts
    }

    private fun cursorToContact(cursor: android.database.Cursor): Contact {
        return Contact(
            id = cursor.getLong(cursor.getColumnIndexOrThrow("id")),
            uuid = cursor.getString(cursor.getColumnIndexOrThrow("uuid")),
            displayName = cursor.getString(cursor.getColumnIndexOrThrow("display_name")) ?: "",
            x25519Pub = cursor.getString(cursor.getColumnIndexOrThrow("x25519_pub")) ?: "",
            ed25519Pub = cursor.getString(cursor.getColumnIndexOrThrow("ed25519_pub")) ?: "",
            isOnline = cursor.getInt(cursor.getColumnIndexOrThrow("is_online")) == 1,
            lastSeen = cursor.getLong(cursor.getColumnIndexOrThrow("last_seen")),
            addedAt = cursor.getLong(cursor.getColumnIndexOrThrow("added_at"))
        )
    }
}

package com.spider.android.storage

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * SQLite 数据库助手 — 消息、联系人、身份元数据。
 */
class DatabaseHelper(context: Context) : SQLiteOpenHelper(
    context, DATABASE_NAME, null, DATABASE_VERSION
) {

    companion object {
        private const val DATABASE_NAME = "spider.db"
        private const val DATABASE_VERSION = 5

        const val TABLE_MESSAGES = "messages"
        const val TABLE_CONTACTS = "contacts"
        const val TABLE_IDENTITY = "identity"
        const val TABLE_SETTINGS = "settings"
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE $TABLE_MESSAGES (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_uuid TEXT NOT NULL,
                to_uuid TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                is_sent INTEGER DEFAULT 0,
                delivery_status TEXT DEFAULT 'pending',
                server_msg_id TEXT DEFAULT '',
                client_msg_id TEXT DEFAULT '',
                is_deadman_warning INTEGER DEFAULT 0,
                is_file INTEGER DEFAULT 0,
                file_name TEXT DEFAULT '',
                file_size INTEGER DEFAULT 0,
                file_path TEXT DEFAULT '',
                mime_type TEXT DEFAULT ''
            )
        """)
        db.execSQL("CREATE INDEX idx_messages_from ON $TABLE_MESSAGES(from_uuid)")
        db.execSQL("CREATE INDEX idx_messages_to ON $TABLE_MESSAGES(to_uuid)")
        db.execSQL("CREATE INDEX idx_messages_timestamp ON $TABLE_MESSAGES(timestamp)")

        db.execSQL("""
            CREATE TABLE $TABLE_CONTACTS (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE NOT NULL,
                display_name TEXT DEFAULT '',
                x25519_pub TEXT DEFAULT '',
                ed25519_pub TEXT DEFAULT '',
                is_online INTEGER DEFAULT 0,
                last_seen INTEGER DEFAULT 0,
                added_at INTEGER DEFAULT 0
            )
        """)
        db.execSQL("CREATE INDEX idx_contacts_uuid ON $TABLE_CONTACTS(uuid)")

        db.execSQL("""
            CREATE TABLE $TABLE_IDENTITY (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE NOT NULL,
                mac_address TEXT DEFAULT '',
                x25519_public TEXT DEFAULT '',
                x25519_private_enc TEXT DEFAULT '',
                ed25519_public TEXT DEFAULT '',
                ed25519_private_enc TEXT DEFAULT '',
                server_host TEXT DEFAULT '',
                server_port INTEGER DEFAULT 0,
                display_name TEXT DEFAULT '',
                encryption_salt TEXT DEFAULT '',
                duress_salt TEXT DEFAULT '',
                duress_pin_hash TEXT DEFAULT '',
                has_duress_pin INTEGER DEFAULT 0,
                unlock_pin_salt TEXT DEFAULT '',
                unlock_pin_hash TEXT DEFAULT ''
            )
        """)

        db.execSQL("""
            CREATE TABLE $TABLE_SETTINGS (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            db.execSQL("ALTER TABLE $TABLE_MESSAGES ADD COLUMN is_deadman_warning INTEGER DEFAULT 0")
        }
        if (oldVersion < 3) {
            db.execSQL("ALTER TABLE $TABLE_MESSAGES ADD COLUMN client_msg_id TEXT DEFAULT ''")
        }
        if (oldVersion < 4) {
            db.execSQL("ALTER TABLE $TABLE_MESSAGES ADD COLUMN file_path TEXT DEFAULT ''")
            db.execSQL("ALTER TABLE $TABLE_MESSAGES ADD COLUMN mime_type TEXT DEFAULT ''")
        }
        if (oldVersion < 5) {
            db.execSQL("ALTER TABLE $TABLE_IDENTITY ADD COLUMN unlock_pin_salt TEXT DEFAULT ''")
            db.execSQL("ALTER TABLE $TABLE_IDENTITY ADD COLUMN unlock_pin_hash TEXT DEFAULT ''")
        }
    }

    override fun onDowngrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_MESSAGES")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_CONTACTS")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_IDENTITY")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_SETTINGS")
        onCreate(db)
    }

    /**
     * 安全擦除所有数据（胁迫擦除时调用）。
     */
    fun wipeAllData() {
        val db = writableDatabase
        db.delete(TABLE_MESSAGES, null, null)
        db.delete(TABLE_CONTACTS, null, null)
        db.delete(TABLE_IDENTITY, null, null)
        db.delete(TABLE_SETTINGS, null, null)
        db.close()
    }
}

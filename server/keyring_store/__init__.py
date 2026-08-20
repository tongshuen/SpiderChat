"""基于 keyring 的服务器凭据存储。"""
from .backend import check_keyring, show_error_popup
from .credentials import (
    get_credential, set_credential, delete_credential,
    get_admin_pin_hash, set_admin_pin_hash,
    get_server_keys, set_server_keys, get_node_id, set_node_id,
    get_keyring_service,
)

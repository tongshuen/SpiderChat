"""
Spider — 客户端安全增强模块。
* ephemeral : 阅后即焚引擎（全局 / 按联系人 / 按正则规则 + 快速/安全删除）
* vault     : 聊天记录加密保险库（按消息分片加解密，支持流式搜索与迁移）
"""
from .ephemeral import (
    EphemeralEngine,
    default_ephemeral_config,
    validate_regex_patterns,
    normalize_delete_mode,
    add_ephemeral_contact,
    remove_ephemeral_contact,
    CONF_EPHEMERAL_ENABLED,
    CONF_EPHEMERAL_MODE,
    CONF_EPHEMERAL_GLOBAL,
    CONF_EPHEMERAL_CONTACTS,
    CONF_EPHEMERAL_REGEX,
)
from .vault import (
    MessageVault,
    VaultError,
    default_vault_config,
    vault_blob_to_text,
    CONF_VAULT_ENABLED,
    CONF_VAULT_PIN_PROTECTED,
    CONF_VAULT_SALT,
    CONF_VAULT_KDF_ITER,
)

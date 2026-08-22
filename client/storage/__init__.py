"""客户端存储模块。"""
# 延迟导入：identity 模块导入 config.profile_path，而 config 可能反向导入存储，
# 此处延迟绑定以避免循环导入。
def __getattr__(name):
    if name in ("save_identity_file", "load_identity_file", "wipe_all_data"):
        from .identity import save_identity_file, load_identity_file, wipe_all_data
        return {"save_identity_file": save_identity_file,
                "load_identity_file": load_identity_file,
                "wipe_all_data": wipe_all_data}[name]
    if name == "MessageStore":
        from .messages import MessageStore
        return MessageStore
    raise AttributeError(name)

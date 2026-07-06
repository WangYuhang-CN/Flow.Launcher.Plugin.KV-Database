from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path

import kv_database

DEFAULT_LANGUAGE = "en"
FLOW_SETTINGS_PATH = Path(os.environ.get("APPDATA", "")) / "FlowLauncher" / "Settings" / "Settings.json"
WINDOWS_UI_LANGUAGE_MAP = {
    0x0804: "zh-cn",
}

TRANSLATIONS = {
    "en": {
        "copy_value_title": "Copy value",
        "copy_value_subtitle": "Press Enter to copy value",
        "copy_key_title": "Copy key",
        "delete_title": "Delete {key}",
        "delete_subtitle": "Delete this entry",
        "empty_subtitle": "; <KEY> to search, ; <KEY> <VALUE> to save or update",
        "recent_suffix": "Recent entry, press Enter to copy value",
        "exact_suffix": "Press Enter to copy value",
        "matched_suffix": "Matched entry, press Enter to copy value",
        "not_found_title": "Not found: {key}",
        "not_found_subtitle": "Continue typing: ; {key} value",
        "key_empty_title": "Key cannot be empty",
        "usage_subtitle": "; <KEY> <VALUE>",
        "value_empty_title": "Value cannot be empty for {key}",
        "save_title": "Save {key}",
        "update_title": "Update {key}",
        "confirm_subtitle": "Press Enter to confirm",
        "help_command_title": "; --help",
        "help_command_subtitle": "Show available commands and shortcuts",
        "help_search_title": "; <KEY>",
        "help_search_subtitle": "Find entries by key and press Enter to copy the value",
        "help_save_title": "; <KEY> <VALUE>",
        "help_save_subtitle": "The first whitespace-separated token is the key; the rest is the value",
        "help_recent_title": ";",
        "help_recent_subtitle": "Show recently updated entries",
        "help_status_title": "; --status",
        "help_status_subtitle": "Check encryption, Windows user binding, and recovery key state",
        "help_recovery_title": "; --recovery",
        "help_recovery_subtitle": "Generate or rotate a recovery key; old keys are never shown",
        "help_unlock_title": "; --unlock <KEY>",
        "help_unlock_subtitle": "Rebind this database to the current Windows user",
        "unknown_command_title": "Unknown command: {command}",
        "unknown_command_subtitle": "Use ; --help to see available commands",
        "status_encrypted_title": "Encrypted storage enabled",
        "status_encrypted_subtitle": "{count} entries stored with encrypted values",
        "status_dpapi_unlocked_title": "Windows user binding ready",
        "status_dpapi_unlocked_subtitle": "This Windows user can unlock the database automatically",
        "status_dpapi_locked_title": "Locked for this Windows user",
        "status_dpapi_locked_subtitle": "Use ; --unlock <KEY> with your recovery key",
        "status_dpapi_missing_title": "No Windows user binding",
        "status_dpapi_missing_subtitle": "Use ; --unlock <KEY> if this database came from another user",
        "status_recovery_enabled_title": "Recovery key configured",
        "status_recovery_enabled_subtitle": "Use ; --recovery to rotate it; the old key will stop working",
        "status_recovery_disabled_title": "No recovery key configured",
        "status_recovery_disabled_subtitle": "Use ; --recovery to generate one and save it yourself",
        "recovery_generate_title": "Generate recovery key",
        "recovery_generate_subtitle": "Press Enter to generate it and copy it to the clipboard; save it now",
        "recovery_rotate_title": "Rotate recovery key",
        "recovery_rotate_subtitle": "Press Enter to replace the old recovery key and copy the new one",
        "unlock_usage_title": "; --unlock <KEY>",
        "unlock_usage_subtitle": "Paste the recovery key after --unlock",
        "unlock_title": "Unlock secure database",
        "unlock_subtitle": "Press Enter to bind this database to the current Windows user",
        "locked_title": "Secure database is locked",
        "locked_subtitle": "Use ; --unlock <KEY> with your recovery key",
        "storage_error_title": "Secure storage error",
        "storage_error_subtitle": "The database could not be decrypted; check the recovery key or database file",
    },
    "zh-cn": {
        "copy_value_title": "复制值",
        "copy_value_subtitle": "按 Enter 复制值",
        "copy_key_title": "复制 Key",
        "delete_title": "删除 {key}",
        "delete_subtitle": "删除这个条目",
        "empty_subtitle": "; <KEY> 查询，; <KEY> <VALUE> 保存或更新",
        "recent_suffix": "最近更新，按 Enter 复制值",
        "exact_suffix": "按 Enter 复制值",
        "matched_suffix": "匹配结果，按 Enter 复制值",
        "not_found_title": "未找到 {key}",
        "not_found_subtitle": "继续输入：; {key} value 可新增",
        "key_empty_title": "Key 不能为空",
        "usage_subtitle": "; <KEY> <VALUE>",
        "value_empty_title": "{key} 的值不能为空",
        "save_title": "保存 {key}",
        "update_title": "更新 {key}",
        "confirm_subtitle": "按 Enter 确认",
        "help_command_title": "; --help",
        "help_command_subtitle": "查看可用命令和快捷输入",
        "help_search_title": "; <KEY>",
        "help_search_subtitle": "按 Key 查找，按 Enter 复制值",
        "help_save_title": "; <KEY> <VALUE>",
        "help_save_subtitle": "第一个空白分隔片段是 Key，后面的内容是值",
        "help_recent_title": ";",
        "help_recent_subtitle": "显示最近更新的条目",
        "help_status_title": "; --status",
        "help_status_subtitle": "查看加密、Windows 用户绑定和恢复密钥状态",
        "help_recovery_title": "; --recovery",
        "help_recovery_subtitle": "生成或轮换恢复密钥；不会显示旧密钥",
        "help_unlock_title": "; --unlock <KEY>",
        "help_unlock_subtitle": "把数据库重新绑定到当前 Windows 用户",
        "unknown_command_title": "未知命令：{command}",
        "unknown_command_subtitle": "使用 ; --help 查看可用命令",
        "status_encrypted_title": "已启用加密存储",
        "status_encrypted_subtitle": "当前有 {count} 个条目，值已加密保存",
        "status_dpapi_unlocked_title": "Windows 用户绑定正常",
        "status_dpapi_unlocked_subtitle": "当前 Windows 用户可以自动解锁数据库",
        "status_dpapi_locked_title": "当前 Windows 用户无法解锁",
        "status_dpapi_locked_subtitle": "请使用 ; --unlock <KEY> 输入恢复密钥",
        "status_dpapi_missing_title": "未绑定 Windows 用户",
        "status_dpapi_missing_subtitle": "如果数据库来自其他用户，请使用 ; --unlock <KEY>",
        "status_recovery_enabled_title": "已配置恢复密钥",
        "status_recovery_enabled_subtitle": "使用 ; --recovery 可轮换，旧密钥会失效",
        "status_recovery_disabled_title": "未配置恢复密钥",
        "status_recovery_disabled_subtitle": "使用 ; --recovery 生成，并自行保存",
        "recovery_generate_title": "生成恢复密钥",
        "recovery_generate_subtitle": "按 Enter 生成并复制到剪贴板；请立刻保存",
        "recovery_rotate_title": "轮换恢复密钥",
        "recovery_rotate_subtitle": "按 Enter 替换旧恢复密钥，并复制新密钥",
        "unlock_usage_title": "; --unlock <KEY>",
        "unlock_usage_subtitle": "把恢复密钥粘贴在 --unlock 后面",
        "unlock_title": "解锁安全数据库",
        "unlock_subtitle": "按 Enter 绑定到当前 Windows 用户",
        "locked_title": "安全数据库已锁定",
        "locked_subtitle": "请使用 ; --unlock <KEY> 输入恢复密钥",
        "storage_error_title": "安全存储错误",
        "storage_error_subtitle": "数据库无法解密；请检查恢复密钥或数据库文件",
    },
}


class I18n:
    def __init__(self, language: str | None = None):
        self.language = resolve_language(language)

    def t(self, message_key: str, **kwargs) -> str:
        language_messages = TRANSLATIONS.get(self.language, TRANSLATIONS[DEFAULT_LANGUAGE])
        template = language_messages.get(message_key, TRANSLATIONS[DEFAULT_LANGUAGE][message_key])
        return template.format(**kwargs)


def resolve_language(preferred_language: str | None = None) -> str:
    override = os.environ.get("KV_DATABASE_LANG") or preferred_language
    if override:
        return normalize_language(override)

    flow_language = read_flow_launcher_language()
    if flow_language:
        return normalize_language(flow_language)

    windows_language = read_windows_ui_language()
    if windows_language:
        return normalize_language(windows_language)

    return DEFAULT_LANGUAGE


def normalize_language(language: str) -> str:
    normalized = language.strip().lower().replace("_", "-")
    if normalized in TRANSLATIONS:
        return normalized
    return DEFAULT_LANGUAGE


def read_flow_launcher_language() -> str | None:
    try:
        with FLOW_SETTINGS_PATH.open("r", encoding="utf-8") as f:
            settings = json.load(f)
        return settings.get("Language")
    except Exception as exc:
        kv_database.log(f"Could not read Flow Launcher language: {exc}", "DEBUG")
        return None


def read_windows_ui_language() -> str | None:
    try:
        language_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        return WINDOWS_UI_LANGUAGE_MAP.get(language_id)
    except Exception as exc:
        kv_database.log(f"Could not read Windows UI language: {exc}", "DEBUG")
        return None

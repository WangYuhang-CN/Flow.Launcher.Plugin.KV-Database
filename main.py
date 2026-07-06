from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes

from i18n import I18n
import kv_database
from secure_crypto import CryptoError
from flowlauncher2 import FlowLauncher
from kv_database import KVEntry, KVStore, KVStoreLockedError, KVStoreRecoveryError

try:
    import pyperclip
except ImportError:
    pyperclip = None


ICON_PATH = os.path.join("images", "kv_database_logo.png")
MAX_RESULTS = 8
COMMAND_HELP_ITEMS = (
    ("help_command_title", "help_command_subtitle", None),
    ("help_status_title", "help_status_subtitle", None),
    ("help_recovery_title", "help_recovery_subtitle", None),
    ("help_unlock_title", "help_unlock_subtitle", "; --unlock"),
)


class KVDatabase(FlowLauncher):
    """Flow Launcher key-value database plugin."""

    def __init__(self):
        self._store: KVStore | None = None
        self._store_error: Exception | None = None
        self.i18n = I18n()
        super().__init__()

    @property
    def store(self) -> KVStore:
        if self._store is not None:
            return self._store
        if self._store_error is not None:
            raise self._store_error

        try:
            self._store = KVStore()
            return self._store
        except Exception as exc:
            self._store_error = exc
            kv_database.log(f"Storage initialization failed: {exc}", "ERROR")
            raise

    def query(self, query: str = "") -> list[dict]:
        text = query.strip()
        kv_database.log(f"Query received; length={len(text)}", "DEBUG")

        try:
            if not text:
                return self._empty_results()

            if text.startswith("--") or text in ("-h",):
                return self._command_results(text)

            key, value = self._parse_query(text)
            if value is not None:
                return self._save_results(key, value)

            return self._lookup_results(key)
        except KVStoreLockedError:
            return self._locked_results()
        except CryptoError as exc:
            kv_database.log(f"Storage crypto error: {exc}", "ERROR")
            return self._storage_error_results()
        except Exception as exc:
            kv_database.log(f"Storage error: {exc}", "ERROR")
            return self._storage_error_results()

    def context_menu(self, data) -> list[dict]:
        kv_database.log(f"Context menu requested; data_type={type(data).__name__}", "INFO")

        if not isinstance(data, dict):
            kv_database.log("Context menu skipped; data is not a dict.", "WARNING")
            return []

        data_keys = sorted(str(data_key) for data_key in data.keys())
        kv_database.log(f"Context menu data keys: {data_keys}", "INFO")

        key = data.get("key", "")
        if not key:
            kv_database.log("Context menu skipped; missing key in context data.", "WARNING")
            return []

        results = [
            self._result(
                title=self.i18n.t("copy_value_title"),
                subtitle=self.i18n.t("copy_value_subtitle"),
                method="copy_entry_value",
                parameters=[key],
            ),
            self._result(
                title=self.i18n.t("copy_key_title"),
                subtitle=key,
                method="copy_value",
                parameters=[key],
            ),
            self._result(
                title=self.i18n.t("delete_title", key=key),
                subtitle=self.i18n.t("delete_subtitle"),
                method="delete_key",
                parameters=[key],
            ),
        ]
        kv_database.log(f"Context menu built; key={key!r}; result_count={len(results)}", "INFO")
        return results

    def load_context_menus(self, data) -> list[dict]:
        kv_database.log(f"Load context menus requested; data_type={type(data).__name__}", "INFO")
        return self.context_menu(data)

    def copy_value(self, value: str) -> None:
        self._copy_to_clipboard(value)

    def copy_entry_value(self, key: str) -> None:
        try:
            entry = self.store.get(key)
        except (KVStoreLockedError, CryptoError) as exc:
            kv_database.log(f"Copy failed; database locked or unreadable: {exc}", "WARNING")
            return
        if entry is None:
            kv_database.log(f"Copy failed; key not found: {key}", "WARNING")
            return
        self._copy_to_clipboard(entry.value)

    def _copy_to_clipboard(self, value: str) -> bool:
        if self._copy_with_pyperclip(value) or self._copy_with_windows_api(value):
            kv_database.log("Copied value to clipboard.", "INFO")
            return True
        kv_database.log("Clipboard copy failed.", "ERROR")
        return False

    @staticmethod
    def _copy_with_pyperclip(value: str) -> bool:
        if pyperclip is None:
            return False
        try:
            pyperclip.copy(value)
            return True
        except Exception as exc:
            kv_database.log(f"pyperclip copy failed: {exc}", "WARNING")
            return False

    @staticmethod
    def _copy_with_windows_api(value: str) -> bool:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.EmptyClipboard.argtypes = []
        user32.EmptyClipboard.restype = wintypes.BOOL
        user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        user32.SetClipboardData.restype = wintypes.HANDLE
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wintypes.BOOL
        kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalLock.restype = wintypes.LPVOID
        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalUnlock.restype = wintypes.BOOL
        kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalFree.restype = wintypes.HGLOBAL

        cf_unicode_text = 13
        gmem_moveable = 0x0002
        data = (value + "\0").encode("utf-16-le")
        handle = kernel32.GlobalAlloc(gmem_moveable, len(data))
        if not handle:
            kv_database.log("GlobalAlloc failed for clipboard data.", "WARNING")
            return False

        locked = kernel32.GlobalLock(handle)
        if not locked:
            kernel32.GlobalFree(handle)
            kv_database.log("GlobalLock failed for clipboard data.", "WARNING")
            return False

        ctypes.memmove(locked, data, len(data))
        kernel32.GlobalUnlock(handle)

        opened = False
        for _ in range(10):
            if user32.OpenClipboard(None):
                opened = True
                break
            time.sleep(0.05)

        if not opened:
            kernel32.GlobalFree(handle)
            kv_database.log("OpenClipboard failed.", "WARNING")
            return False

        try:
            if not user32.EmptyClipboard():
                kv_database.log("EmptyClipboard failed.", "WARNING")
                return False
            if not user32.SetClipboardData(cf_unicode_text, handle):
                kv_database.log("SetClipboardData failed.", "WARNING")
                return False
            handle = None
            return True
        finally:
            user32.CloseClipboard()
            if handle:
                kernel32.GlobalFree(handle)

    def save_entry(self, key: str, value: str) -> None:
        try:
            self.store.upsert(key, value)
        except (KVStoreLockedError, CryptoError) as exc:
            kv_database.log(f"Save failed; database locked or unreadable: {exc}", "WARNING")

    def delete_key(self, key: str) -> None:
        self.store.delete(key)

    def create_or_rotate_recovery_key(self) -> None:
        try:
            recovery_key = self.store.create_or_rotate_recovery_key()
        except (KVStoreLockedError, CryptoError) as exc:
            kv_database.log(f"Recovery key generation failed: {exc}", "WARNING")
            return
        if self._copy_to_clipboard(recovery_key):
            kv_database.log("Recovery key copied to clipboard.", "INFO")

    def unlock_with_recovery_key(self, recovery_key: str) -> None:
        try:
            self.store.unlock_with_recovery_key(recovery_key.strip())
        except KVStoreRecoveryError as exc:
            kv_database.log(f"Unlock failed: {exc}", "WARNING")

    def replace_query(self, query: str) -> None:
        self._safe_print_json(
            {
                "method": "Flow.Launcher.ChangeQuery",
                "parameters": [query, False],
            }
        )

    def _empty_results(self) -> list[dict]:
        entries = self.store.recent(MAX_RESULTS)
        help_result = self._help_result("help_command_title", "help_command_subtitle")
        if not entries:
            return [
                self._result(
                    title="KV Database",
                    subtitle=self.i18n.t("empty_subtitle"),
                ),
                help_result,
            ]

        recent_results = [
            self._entry_result(entry, subtitle_suffix=self.i18n.t("recent_suffix"))
            for entry in entries[: MAX_RESULTS - 1]
        ]
        recent_results.append(help_result)
        return recent_results

    def _help_results(self) -> list[dict]:
        return [
            self._help_result("help_command_title", "help_command_subtitle"),
            self._help_result("help_search_title", "help_search_subtitle", replacement=";"),
            self._help_result("help_save_title", "help_save_subtitle", replacement=";"),
            self._help_result("help_recent_title", "help_recent_subtitle"),
            self._help_result("help_status_title", "help_status_subtitle"),
            self._help_result("help_recovery_title", "help_recovery_subtitle"),
            self._help_result("help_unlock_title", "help_unlock_subtitle", replacement="; --unlock"),
        ]

    def _command_results(self, text: str) -> list[dict]:
        command, argument = self._parse_query(text)
        if command == "--":
            return self._command_suggestion_results(command)
        if command in ("--help", "-h"):
            return self._help_results()
        if command == "--status":
            return self._status_results()
        if command == "--recovery":
            return self._recovery_results()
        if command == "--unlock":
            return self._unlock_results(argument)
        suggestions = self._command_suggestion_results(command)
        if suggestions:
            return suggestions
        return [
            self._result(
                title=self.i18n.t("unknown_command_title", command=command),
                subtitle=self.i18n.t("unknown_command_subtitle"),
            )
        ]

    def _command_suggestion_results(self, prefix: str) -> list[dict]:
        results = []
        for title_key, subtitle_key, replacement in COMMAND_HELP_ITEMS:
            command = self.i18n.t(title_key)
            command_without_action = command.removeprefix(";").strip()
            if command_without_action.startswith(prefix):
                results.append(self._help_result(title_key, subtitle_key, replacement=replacement))
        return results

    def _status_results(self) -> list[dict]:
        status = self.store.security_status()
        if status.dpapi_unlockable:
            unlock_title = self.i18n.t("status_dpapi_unlocked_title")
            unlock_subtitle = self.i18n.t("status_dpapi_unlocked_subtitle")
        elif status.dpapi_configured:
            unlock_title = self.i18n.t("status_dpapi_locked_title")
            unlock_subtitle = self.i18n.t("status_dpapi_locked_subtitle")
        else:
            unlock_title = self.i18n.t("status_dpapi_missing_title")
            unlock_subtitle = self.i18n.t("status_dpapi_missing_subtitle")

        recovery_title = (
            self.i18n.t("status_recovery_enabled_title")
            if status.recovery_configured
            else self.i18n.t("status_recovery_disabled_title")
        )
        recovery_subtitle = (
            self.i18n.t("status_recovery_enabled_subtitle")
            if status.recovery_configured
            else self.i18n.t("status_recovery_disabled_subtitle")
        )

        return [
            self._result(
                title=self.i18n.t("status_encrypted_title"),
                subtitle=self.i18n.t("status_encrypted_subtitle", count=status.entry_count),
            ),
            self._result(title=unlock_title, subtitle=unlock_subtitle),
            self._result(title=recovery_title, subtitle=recovery_subtitle),
        ]

    def _recovery_results(self) -> list[dict]:
        status = self.store.security_status()
        if not status.dpapi_unlockable:
            return self._locked_results()

        if status.recovery_configured:
            title = self.i18n.t("recovery_rotate_title")
            subtitle = self.i18n.t("recovery_rotate_subtitle")
        else:
            title = self.i18n.t("recovery_generate_title")
            subtitle = self.i18n.t("recovery_generate_subtitle")

        return [
            self._result(
                title=title,
                subtitle=subtitle,
                method="create_or_rotate_recovery_key",
            )
        ]

    def _unlock_results(self, recovery_key: str | None) -> list[dict]:
        if not recovery_key:
            return [
                self._help_result(
                    "unlock_usage_title",
                    "unlock_usage_subtitle",
                    replacement="; --unlock",
                )
            ]
        return [
            self._result(
                title=self.i18n.t("unlock_title"),
                subtitle=self.i18n.t("unlock_subtitle"),
                method="unlock_with_recovery_key",
                parameters=[recovery_key],
            )
        ]

    def _locked_results(self) -> list[dict]:
        return [
            self._result(
                title=self.i18n.t("locked_title"),
                subtitle=self.i18n.t("locked_subtitle"),
            )
        ]

    def _storage_error_results(self) -> list[dict]:
        return [
            self._result(
                title=self.i18n.t("storage_error_title"),
                subtitle=self.i18n.t("storage_error_subtitle"),
            )
        ]

    def _lookup_results(self, key: str) -> list[dict]:
        exact = self.store.get(key)
        matches = self.store.search(key, MAX_RESULTS)

        results = []
        if exact is not None:
            results.append(self._entry_result(exact, subtitle_suffix=self.i18n.t("exact_suffix")))
            matches = [entry for entry in matches if entry.key != exact.key]

        results.extend(
            self._entry_result(entry, subtitle_suffix=self.i18n.t("matched_suffix"))
            for entry in matches[: MAX_RESULTS - len(results)]
        )

        if results:
            return results

        return [
            self._result(
                title=self.i18n.t("not_found_title", key=key),
                subtitle=self.i18n.t("not_found_subtitle", key=key),
            )
        ]

    def _save_results(self, key: str, value: str) -> list[dict]:
        if not key:
            return [
                self._result(
                    title=self.i18n.t("key_empty_title"),
                    subtitle=self.i18n.t("usage_subtitle"),
                )
            ]
        if not value:
            return [
                self._result(
                    title=self.i18n.t("value_empty_title", key=key),
                    subtitle=self.i18n.t("usage_subtitle"),
                )
            ]

        existing = self.store.get(key)
        if existing is None:
            title = self.i18n.t("save_title", key=key)
        else:
            title = self.i18n.t("update_title", key=key)

        return [
            self._result(
                title=title,
                subtitle=self.i18n.t("confirm_subtitle"),
                method="save_entry",
                parameters=[key, value],
            )
        ]

    def _entry_result(self, entry: KVEntry, subtitle_suffix: str) -> dict:
        return self._result(
            title=entry.key,
            subtitle=subtitle_suffix,
            method="copy_entry_value",
            parameters=[entry.key],
            context_data={"key": entry.key},
        )

    def _help_result(
        self,
        title_key: str,
        subtitle_key: str,
        replacement: str | None = None,
    ) -> dict:
        command = self.i18n.t(title_key)
        return self._result(
            title=command,
            subtitle=self.i18n.t(subtitle_key),
            method="replace_query",
            parameters=[replacement or command],
            dont_hide_after_action=True,
        )

    @staticmethod
    def _parse_query(text: str) -> tuple[str, str | None]:
        parts = text.split(maxsplit=1)
        key = parts[0].strip() if parts else ""
        value = parts[1].strip() if len(parts) > 1 else None
        return key, value

    @staticmethod
    def _result(
        title: str,
        subtitle: str,
        method: str | None = None,
        parameters: list | None = None,
        context_data: dict | None = None,
        dont_hide_after_action: bool = False,
    ) -> dict:
        result = {
            "Title": title,
            "SubTitle": subtitle,
            "IcoPath": ICON_PATH,
        }
        if method:
            result["JsonRPCAction"] = {
                "Method": method,
                "Parameters": parameters or [],
                "DontHideAfterAction": dont_hide_after_action,
            }
        if context_data is not None:
            result["ContextData"] = context_data
        return result


if __name__ == "__main__":
    KVDatabase()

<div align="center">
  <img src="images/kv_database_logo.png" width="96" height="96" alt="KV Database logo">

  <h1>KV Database</h1>

  <p>
    A lightweight key-value database plugin for
    <a href="https://www.flowlauncher.com/">Flow Launcher</a>.
  </p>

  <p>
    <a href="plugin.json"><img alt="Flow Launcher plugin" src="https://img.shields.io/badge/Flow%20Launcher-plugin-1677ff"></a>
    <img alt="Language" src="https://img.shields.io/badge/language-python-3776ab">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  </p>
</div>

## Overview

KV Database turns Flow Launcher into a small local key-value lookup tool.
It is designed for snippets, tokens, short notes, IDs, URLs, and other values
you want to retrieve quickly from the launcher.

Values are hidden from the result list by default. Selecting a result copies
the real value to the Windows clipboard.

## Features

- Search, copy, create, and update key-value entries from Flow Launcher.
- Keep values hidden in launcher results until they are copied.
- Store values encrypted in a local SQLite database.
- Use Windows DPAPI for automatic unlock on the current Windows user.
- Optionally create a recovery key for moving the database to another user or PC.
- Follow Flow Launcher's language setting for plugin text.
- Use the result menu to copy keys or delete entries.

## Installation

Until the plugin is published, install it manually:

1. Copy this plugin folder into your Flow Launcher plugins directory.

   ```text
   %APPDATA%\FlowLauncher\Plugins\KV Database
   ```

2. Restart Flow Launcher or reload plugins from the Flow settings.
3. Use `;` in Flow Launcher to start using the plugin.

No third-party Python package is required.

## Usage

| Input | Action |
| --- | --- |
| `;` | Show recently updated entries |
| `; <KEY>` | Search `KEY` and copy the selected value on Enter |
| `; <KEY> <VALUE>` | Create or update `KEY` with `VALUE` after pressing Enter |
| `; --help` | Show usage help |
| `; --status` | Show encryption and recovery status |
| `; --recovery` | Generate or rotate a recovery key |
| `; --unlock <KEY>` | Unlock a copied database with a recovery key |

Examples:

```text
; github
; github https://github.com/example
; example-token redacted-value
; --help
; --status
; --recovery
; --unlock KVDB-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
```

Keys use the first whitespace-separated token. Values may contain spaces.

```text
; my-key value with spaces
```

This stores:

```text
key   = my-key
value = value with spaces
```

## Commands

Plugin commands start with `--` so they do not conflict with normal keys.

| Command | Description |
| --- | --- |
| `; --help` | Shows the command and usage summary. |
| `; --status` | Shows whether encrypted storage, DPAPI unlock, and recovery key support are available. |
| `; --recovery` | Generates a recovery key when none exists, or rotates the current recovery key. |
| `; --unlock <KEY>` | Uses a recovery key to unlock a copied database and bind it to the current Windows user. |

`--recovery` never displays an existing recovery key. A recovery key is shown
only when it is created or rotated, and the old key stops working after rotation.

## Result Menu

Open the result menu on an existing entry to copy its key or delete the entry.

## Storage

Data is stored locally in SQLite:

```text
db/kv.sqlite3
```

The database file is created automatically on first use and is ignored by Git.
Values are encrypted by default. Keys and timestamps remain plaintext so the
plugin can search and sort entries quickly.

## Security

KV Database hides values from the Flow Launcher UI, but it is not a password
manager.

Values are encrypted before they are stored in `db/kv.sqlite3`. The plugin
generates a random data key, encrypts entry values with AES-GCM, and protects
the data key with Windows DPAPI for the current Windows user.

The normal user experience does not change: save with `; <KEY> <VALUE>`, search with
`; <KEY>`, and press Enter to copy the value. There is no master password prompt
for daily use.

By default, the encrypted database is bound to the current Windows user. To move
the database to another Windows user or PC, run:

```text
; --recovery
```

Press Enter to generate a recovery key and copy it to the clipboard. Save it
yourself. The recovery key is not stored in plaintext and cannot be displayed
again later. Running `; --recovery` again rotates the recovery key and invalidates
the old one.

After copying `db/kv.sqlite3` to another user or PC, unlock it with:

```text
; --unlock <KEY>
```

The plugin will use the recovery key once and then bind the database to the new
Windows user with DPAPI.

### Security Limits

Also note that while result values are hidden, the value you type into the Flow
Launcher input box is still visible while entering `; <KEY> <VALUE>`.

Values copied to the clipboard can be read by other local software while they
remain on the clipboard.

This protects values at rest in the SQLite database. It does not protect against
malware running as the same Windows user, screen capture while typing, clipboard
monitoring, or someone who has both the database and your recovery key.

## Localization

UI text follows Flow Launcher's configured language:

- `zh-cn` uses Simplified Chinese.
- All other languages currently fall back to English.

For local testing, override language detection with:

```powershell
$env:KV_DATABASE_LANG = "zh-cn"
```

or:

```powershell
$env:KV_DATABASE_LANG = "en"
```

To add another language, add a new entry to `TRANSLATIONS` in `i18n.py`.

## License

MIT

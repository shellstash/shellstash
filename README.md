# ShellStash

**ShellStash** is a hacker-themed, terminal-style bookmark manager built in Python. It allows you to securely store, organize, and manage bookmarks with URLs, titles, categories, usernames, and passwords. Bookmarks are encrypted using Fernet (symmetric encryption), and the app features a command-line interface, drag-and-drop sorting, and category management.

![ShellStash Screenshot](screenshots/shellstash_password.png) 

## Features

- **Secure Storage**: Bookmarks are encrypted with a user-defined password using `cryptography.Fernet`.
- **Bookmark Management**: Add, edit, delete, and search bookmarks with auto-fetched titles.
- **Categories**: Organize bookmarks into categories, with sorting, renaming, and filtering via a tree view.
- **Credentials**: Store and copy usernames/passwords, with a show/hide toggle.
- **Navigation**: Drag-and-drop bookmarks, move up/down, and lock/unlock category boundaries.
- **Import/Export**: Import from HTML (browser-compatible) and export to HTML/TXT.
- **Customizable UI**: Toggle between "default" (dark green) and "alternative" (black-green) color schemes.
- **Command-Line Interface**: Execute commands (`new`, `edit`, `delete`, etc.) via a prompt.
- **Shortcuts**: Ctrl+N (new), Ctrl+O (open), Ctrl+D (delete), Ctrl+E (edit), Ctrl+T (tree).
- **Help System**: Detailed in-app guide with usage tips and troubleshooting.

## Installation

### Prerequisites
- Python 3.6+
- Required packages: `cryptography`, `pyperclip`, `beautifulsoup4`, `requests`

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/ShellStash/shellstash.git
   cd shellstash

Install dependencies:
bash

pip install cryptography pyperclip beautifulsoup4 requests

Run the application:
bash

python shellstash.py

First Launch
Set a password to encrypt your bookmarks (entered twice for confirmation).

Use this password to unlock bookmarks on subsequent launches.

Note: There’s no password recovery; keep it safe!

Usage
Main Interface:
Top: Command buttons ([new], [edit], etc.) and search bar.

Middle: Credential display with [show]/[hide] toggle.

Center: Bookmark list, grouped by categories.

Bottom: Command prompt ($) for manual commands.

Common Tasks:
Add Bookmark: Click [new] or type new. Enter URL, title (optional), category, username, password.

Edit/Delete: Select a bookmark, use [edit]/[delete] or type edit/delete.

Search: Type in the search bar to filter by title/URL.

Categories: Use [tree] to sort/rename categories or toggle visibility.

Credentials: Select a bookmark, use [show] to view, [copy] to copy username/password.

Move Bookmarks: Drag-and-drop or use [↑]/[↓] buttons. Toggle []/[] for cross-category movement.

Commands:

new, edit, delete, tree, open, copy, import, export, passwd, help, swap, exit

Type in the prompt or use buttons/shortcuts.

Import/Export:
Import: Load HTML bookmark files (e.g., from Chrome/Firefox).

Export: Save as HTML (browser-compatible) and TXT (includes unencrypted credentials—use cautiously).

Screenshots
[Main Interface:](screenshots/shellstash_main.png) 
[Tree View:](screenshots/shellstash_tree.png) 
[Edit:](screenshots/shellstash_edit.png) 

Security Notes
Bookmarks are stored in bookmarks.json.enc, encrypted with your password.

The salt.bin file is required for decryption.

TXT exports contain unencrypted passwords; handle with care.

No password recovery is available due to encryption design.

Contributing
Contributions are welcome! Please follow these steps:
Fork the repository.

Create a feature branch (git checkout -b feature/your-feature).

Commit changes (git commit -m "Add your feature").

Push to the branch (git push origin feature/your-feature).

Open a Pull Request.

Ideas for Contributions
Password recovery hint feature.

Encrypted TXT export option.

Undo functionality for actions.

Improved drag-and-drop UX.

High-contrast mode for accessibility.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Support
If you find ShellStash useful, consider supporting its development:
BTC Address: bc1qs8g0eju0gkwtzjhh43sxdwm8yf4anmk29spq2l

Copy via the [help] command in the app.

For issues or feature requests, open an Issue on GitHub.

Troubleshooting
Wrong Password: Double-check your password. If lost, delete bookmarks.json.enc and salt.bin to start fresh (loses data).

Import Issues: Ensure HTML files follow the Netscape bookmark format.

Category Movement: If bookmarks won’t move between categories, toggle to [].

Errors: Check the prompt for error messages or consult the [help] guide.

Happy hacking! 


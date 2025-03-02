# Hash & ZIP Cracker Pro

**Hash & ZIP Cracker Pro** is a versatile and powerful tool designed to help security professionals, ethical hackers, and enthusiasts crack hashes and ZIP file passwords using a variety of popular wordlists. This tool features an intuitive graphical user interface (GUI) built using Python's Tkinter library.

### Features

- **Hash Cracking**: Supports MD5, SHA-1, SHA-256, NTLM, and bcrypt hash algorithms.
- **ZIP Cracking**: Cracks password-protected ZIP files.
- **Wordlist Support**: Use custom wordlists or preset wordlists like `rockyou.txt` and `SecLists`.
- **Progress Tracking**: Real-time cracking progress shown with a progress bar.
- **Multithreaded**: Runs the cracking process in a separate thread to ensure smooth GUI performance.
- **Cross-platform**: Built in Python, compatible with Windows, macOS, and Linux.

### Requirements

- Python 3.x
- Tkinter
- bcrypt
- hashlib
- zipfile

Installation
Code the main code.

Usage

    Select Attack Type: Choose between Hash Attack or ZIP Attack from the dropdown menu.
    For Hash Attack: Enter the hash to crack, select the hash type (e.g., SHA-256), and specify the wordlist path.
    For ZIP Attack: Browse and select a ZIP file to crack, and specify the wordlist path.
    Start Cracking: Click "Start Attack" to begin the process. The tool will display real-time progress and results.
    Stop Cracking: Click "Stop Attack" to halt the process at any time.

Preset Wordlists

    rockyou.txt: A popular wordlist used for password cracking.
    SecLists: A larger wordlist that contains common passwords.

You can load these preset wordlists with the "Use rockyou" or "Use SecLists" buttons.
GUI Overview

    Target Hash: Input field for entering the hash to be cracked.
    Hash Type: Dropdown for selecting the type of hash (e.g., MD5, SHA256).
    ZIP File: Input field for selecting a ZIP file to crack.
    Wordlist Path: Input field for specifying the path to the wordlist.
    Progress Bar: Displays the progress of the attack.
    Result Display: Shows the current password being tested and final results.

Contributing

    Fork the repository.
    Create a new branch (git checkout -b feature-name).
    Make your changes.
    Commit your changes (git commit -m 'Add feature').
    Push to the branch (git push origin feature-name).
    Create a new Pull Request.
 

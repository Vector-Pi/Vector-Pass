```markdown```
# 🔐 Secure Password Manager - User Guide

## 📖 Table of Contents
- [Introduction](#introduction)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [GPG Setup](#gpg-setup)
- [Configuration Files](#configuration-files)
- [First Time Setup](#first-time-setup)
- [Using the Application](#using-the-application)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)

## 🌟 Introduction

Welcome to the **Secure Password Manager** - a comprehensive password management solution that combines strong password generation with military-grade encryption. This application features:

- **Smart Password Generation** with leaked password detection
- **Dual-Layer Encryption** (AES + GPG)
- **Password Strength Analysis**
- **Secure Encrypted Vault** storage
- **Cross-platform Compatibility**

## 💻 System Requirements

### Minimum Requirements
- **OS**: Windows 10+, macOS 10.13+, or Ubuntu 18.04+
- **Python**: 3.8 or higher
- **RAM**: 4GB
- **Storage**: 200MB free space

### Recommended
- **OS**: Windows 11, macOS 12+, or Ubuntu 20.04+
- **Python**: 3.9+
- **RAM**: 8GB
- **Storage**: 500MB free space

## 🚀 Installation

### Step 1: Install Python Dependencies

```bash
# Clone or download the project files
cd password_manager

# Install required packages
pip install -r requirements.txt
```

If you don't have a `requirements.txt`, install manually:

```bash
pip install cryptography>=3.4.8
pip install python-gnupg>=0.4.8
pip install passlib>=1.7.4
pip install pyperclip>=1.8.2
pip install colorama>=0.4.4
```

### Step 2: Install GPG

#### 🪟 Windows
1. Download from [Gpg4win](https://www.gpg4win.org/)
2. Run the installer with administrative privileges
3. Choose "Complete" installation
4. Add to PATH during installation
5. Restart your command prompt/terminal

#### 🍎 macOS
```bash
# Using Homebrew
brew install gnupg

# OR using MacPorts
sudo port install gnupg
```

#### 🐧 Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install gnupg gnupg-agent pinentry-curses
```

#### 🐧 Linux (CentOS/RHEL/Fedora)
```bash
# CentOS/RHEL
sudo yum install gnupg2

# Fedora
sudo dnf install gnupg2
```

### Step 3: Verify GPG Installation

Open a new terminal/command prompt and run:
```bash
gpg --version
```

You should see output similar to:
```
gpg (GnuPG) 2.2.27
libgcrypt 1.8.7
```

## 🔐 GPG Setup

### Creating Your GPG Key

1. **Open terminal/command prompt**

2. **Generate a new key pair:**
   ```bash
   gpg --full-generate-key
   ```

3. **Follow the prompts:**
   - **Key type**: Press Enter for default (RSA and RSA)
   - **Key size**: Enter `4096`
   - **Expiration**: Choose based on your preference (e.g., `1y` for 1 year)
   - **Real name**: Enter your full name
   - **Email address**: Enter your email
   - **Comment**: Optional comment
   - **Passphrase**: Choose a **strong passphrase** (you'll need this later)

4. **Note your key ID:**
   After generation, you'll see something like:
   ```
   gpg: key A1B2C3D4E5F6G7H8 marked as ultimately trusted
   ```
   Write down `A1B2C3D4E5F6G7H8` (your actual key ID will be different)

### Alternative Key Generation (Quick)
```bash
gpg --batch --generate-key <<EOF
%echo Generating a key...
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Your Name
Name-Email: your.email@example.com
Expire-Date: 1y
Passphrase: your-strong-passphrase-here
%commit
%echo Key generated!
EOF
```

## ⚙️ Configuration Files

### Creating the .gnupg Directory

The application will automatically create the necessary directory structure, but you can manually configure GPG for optimal security.

#### 🪟 Windows
Create folder: `C:\Users\YourUsername\.gnupg\`

#### 🐧 Linux/macOS
The folder `~/.gnupg/` should be created automatically when you generate your first key.

### Creating gpg.conf

Create/edit the file: `~/.gnupg/gpg.conf` (Linux/macOS) or `%USERPROFILE%\.gnupg\gpg.conf` (Windows)

```conf
use-agent
pinentry-mode loopback
```

### Creating gpg-agent.conf

Create/edit the file: `~/.gnupg/gpg-agent.conf` (Linux/macOS) or `%USERPROFILE%\.gnupg\gpg-agent.conf` (Windows)

```conf
allow-loopback-pinentry
```


### Reload GPG Agent

After creating configuration files:

```bash
# Restart the agent
echo RELOADAGENT | gpg-connect-agent
```

## 🛠️ First Time Setup

### Step 1: Add Additional Leaked Password Databases (If Required)
*Some of the files are already added in the directory, add only if you want additional security, adding will increase loading time of the program* 

1. **Download common password lists:**
   - [RockYou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt) (~140MB)
   - [10-million-password-list-top-1000000.txt](https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt)

2. **Place files in the data directory:**
   ```
   password_manager/
   └── data/
       └── leaked_passwords/
           ├── rockyou.txt
           └── common_passwords.txt
   ```

   *Note: The application will work without these files, but leaked password detection will be limited.*

### Step 2: Run the Application
*Please be patient, it takes around one minute to load, if you want better performance, you may remove some of the files from data/leaked_passwords directory however doing it is not reccomended*
```bash
cd password_manager
python main.py
```

### Step 3: Initial Vault Setup

When you first run the application:

1. **Choose "Manage Passwords"** from the main menu
2. **Set up your vault:**
   - Enter a vault name (or press Enter for default)
   - Set a strong AES encryption password
   - Confirm the password

3. **The application will:**
   - Create the encrypted vault
   - Set up GPG encryption with your key
   - Create necessary directory structures

## 📱 Using the Application

### Main Menu Options

#### 1. Generate Password
- **Customizable length** (8-64 characters)
- **Character set options** (uppercase, lowercase, numbers, special)
- **Leaked password detection**
- **Strength analysis**
- **Clipboard copying**

**Example:**
```
--- Password Generator ---
Password length (default 16): 20

Generated Password: Xk8#pL$2@qZwR9*vMnB7!
Strength: Very Strong
Entropy: 128.45 bits
```

#### 2. Check Password Strength
- **Comprehensive strength analysis**
- **Entropy calculation**
- **Pattern detection**
- **Leaked password checking**
- **Improvement suggestions**

**Example:**
```
Enter password to check: **********

Strength Analysis:
Strength: Weak (2/8)
Length: 6 characters
Entropy: 28.00 bits

Recommendations:
  - Password should be at least 8 characters long
  - Add more character types (uppercase, numbers, special)
  - This password has been found in data breaches - DO NOT USE!
```

#### 3. Manage Passwords
- **Add new entries** (service, username, password, URL, notes)
- **List all entries**
- **Search entries**
- **Retrieve passwords**
- **Auto-copy to clipboard**

### Adding Password Entries

1. Select "Add Entry" from the Password Manager menu
2. Fill in the details:
   - **Service**: Website or application name
   - **Username**: Your login username
   - **Password**: The password (generated or manual)
   - **URL**: Website URL (optional)
   - **Notes**: Additional information (optional)

### Searching and Retrieving

- **List Entries**: View all stored services and usernames
- **Search**: Find entries by service or username
- **Get Password**: Retrieve and copy specific passwords

## 🔧 Troubleshooting

### Common Issues and Solutions

#### ❌ "GPG encryption failed: No GPG keys found"
**Solution:**
```bash
# List your keys to verify
gpg --list-keys

# If no keys, generate one
gpg --full-generate-key
```

#### ❌ "GPG decryption failed: Bad passphrase"
**Solution:**
- Ensure you're using the correct GPG passphrase
- Check if caps lock is enabled
- Try restarting GPG agent: `echo RELOADAGENT | gpg-connect-agent`

#### ❌ "Warning: Leaked password directory not found"
**Solution:**
- Create the directory: `mkdir -p data/leaked_passwords`
- Add password wordlist files to the directory

#### ❌ "ModuleNotFoundError: No module named 'cryptography'"
**Solution:**
```bash
pip install cryptography
# OR
pip install -r requirements.txt
```

#### ❌ Permission Errors (Linux/macOS)
**Solution:**
```bash
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*
```

#### ❌ GPG Agent Not Running
**Solution:**
```bash
echo RELOADAGENT | gpg-connect-agent
```

### Debug Mode

Enable debug output by setting environment variable:
```bash
# Linux/macOS
export PASSWORD_MANAGER_DEBUG=1
python main.py

# Windows
set PASSWORD_MANAGER_DEBUG=1
python main.py
```

## 🛡️ Security Best Practices

### Password Management
- **Use unique passwords** for every service
- **Generate strong passwords** (16+ characters)
- **Enable leaked password detection**
- **Regularly update important passwords**
- **Use passphrases** for memorable yet secure passwords

### Key Security
- **Backup your GPG key**: 
  ```bash
  # Export public key
  gpg --export -a "Your Name" > public.key
  
  # Export private key (secure storage!)
  gpg --export-secret-keys -a "Your Name" > private.key
  ```

- **Store backup keys** in secure offline locations
- **Use strong passphrases** for your GPG key
- **Set key expiration** and renew periodically

### Application Security
- **Lock your computer** when not in use
- **Use full disk encryption**
- **Keep the application updated**
- **Regularly backup your password vault**
- **Use antivirus software**

### Vault Management
- **Regularly export backups** of your vault
- **Test restoration** from backups
- **Keep multiple backup copies** in different locations
- **Secure your backup storage** with encryption

## 🔄 Backup and Recovery

### Exporting Your Vault
1. Use the "Export" function in the application
2. Store encrypted backups in multiple locations
3. Include your GPG key in the backup strategy

### Recovery Process
1. **Restore GPG keys** (if needed):
   ```bash
   gpg --import private.key
   ```

2. **Restore vault file** to `data/vaults/` directory

3. **Use your AES password** and **GPG passphrase** to unlock

## 📞 Support

### Getting Help
- **Check this guide** for common solutions
- **Verify your setup** matches the requirements
- **Enable debug mode** for detailed error information

### Reporting Issues
When reporting issues, please include:
1. **Operating System** and version
2. **Python version** (`python --version`)
3. **GPG version** (`gpg --version`)
4. **Error messages** and debug output
5. **Steps to reproduce** the issue

## 📄 License and Acknowledgments

This application uses:
- **cryptography** for AES encryption
- **python-gnupg** for GPG integration
- **Common password lists** for security checking

*Always use password managers responsibly and keep your encryption keys secure.*

---

**Remember:** The security of your passwords depends on the strength of your master password and the protection of your encryption keys. Never share these with anyone and store them securely.

*Last Updated: 19 October 2025*

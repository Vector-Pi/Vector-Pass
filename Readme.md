# Vector-Pass

A local-first, offline password manager built for people who actually care where their data lives.

No cloud sync. No telemetry. No account creation. No phoning home. Your passwords stay on your machine, encrypted under your keys, and that's the end of it.

## Table of Contents
- [Why This Exists](#why-this-exists)
- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [GPG Setup](#gpg-setup)
- [Usage](#usage)
- [Offline Breach Detection](#offline-breach-detection)
- [Troubleshooting](#troubleshooting)
- [Security Model](#security-model)
- [Security Hardening](#security-hardening)
- [License](#license)

## Why This Exists

Every major password manager eventually wants your data in their cloud. They'll call it "sync" or "backup" or "convenience," but at the end of the day your secrets are sitting on someone else's server, protected by their policies, and subject to their breach disclosures.

Vector-Pass takes a different approach: everything happens locally. Password generation, strength analysis, breach detection against wordlists -- all of it runs on your machine without a single network call. The vault is encrypted with both AES-256 and GPG-4096, so even if someone lifts the file, they need both your passphrase and your GPG key to get anywhere.

Built for people who prefer `gpg --full-generate-key` over "Sign in with Google."

## Features

- **Fully offline** -- zero network calls for any password operation
- **Dual-layer encryption** -- AES-256 (PBKDF2 key derivation, 100k iterations) + GPG-4096 RSA
- **Local breach detection** -- checks passwords against leaked wordlists without uploading anything
- **Bloom filter acceleration** -- handles 50M+ leaked passwords in ~50MB of memory
- **Terminal interface** -- clean menu-driven TUI, no GUI dependencies
- **Portable vaults** -- encrypted vault files you can back up anywhere

## System Requirements

- **OS**: Linux (any distro with GPG >= 2.2), macOS 10.13+, or Windows 10+ with WSL
- **Python**: 3.8+
- **GPG**: 2.2+
- **RAM**: 4GB recommended (for large wordlist processing)
- **Storage**: 200MB base + space for your wordlists

### Installing Dependencies

```bash
# Arch
sudo pacman -S python python-pip gnupg

# Debian/Ubuntu
sudo apt install python3 python3-pip gnupg2

# macOS
brew install python gnupg
```

## Installation

```bash
# Clone
git clone https://github.com/yourusername/Vector-Pass.git
cd Vector-Pass

# Set up a venv (don't install into system Python)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Verify everything works:
```bash
gpg --version
python main.py --help
```

## GPG Setup

Vector-Pass needs a GPG key for the second encryption layer. If you already have one, you can use it. Otherwise:

```bash
# Generate a 4096-bit RSA key
gpg --full-generate-key

# Recommended settings:
#   Key type: RSA (sign and encrypt), 4096-bit
#   Expiry: 1y (rotate regularly)
#   Comment: "Vector-Pass" or similar
```

### Hardened GPG config (optional but recommended)

```bash
chmod 700 ~/.gnupg

cat > ~/.gnupg/gpg.conf << EOF
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
cipher-algo AES256
digest-algo SHA512
compress-algo 2
fixed-list-mode
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
require-cross-certification
no-symkey-cache
throw-keyids
EOF
```

## Usage

```bash
source venv/bin/activate
python main.py
```

The main menu gives you three paths:

1. **Generate Password** -- creates a password of specified length, checks it against breach wordlists, optionally saves to vault
2. **Check Password Strength** -- entropy calculation, pattern detection, breach check, crack time estimate
3. **Password Manager** -- create/load encrypted vaults, add/search/delete entries

### Vault security

Each vault is protected by two independent layers:
1. **AES password** -- your master passphrase (PBKDF2-HMAC-SHA256, 100k iterations)
2. **GPG key** -- your cryptographic identity

You need both to decrypt. Don't store them in the same place.

### Navigation
- Arrow keys or numbers to select
- `Enter` to confirm
- `Esc`/`q` to go back
- `Ctrl+C` to bail out

## Offline Breach Detection

Vector-Pass checks passwords against local wordlists (RockYou, darkc0de, etc.) without ever touching a network. Drop `.txt` files into `data/leaked_passwords/` and the tool picks them up.

For large wordlists (millions of entries), the Bloom filter keeps things fast:

```bash
# Build the filter from your wordlists
python scripts/build_bloom_filter.py

# Options:
#   --wordlist-dir     (default: data/leaked_passwords)
#   --expected-items   (default: 50000000)
#   --false-positive-rate (default: 0.01)
```

The filter uses ~50MB regardless of how many passwords you throw at it. Trade-off is a ~1% false positive rate -- it might occasionally flag a clean password as leaked, but it will never miss an actually leaked one.

## Troubleshooting

### "Failed to generate GPG key"

Usually a GPG agent conflict:
```bash
pkill gpg-agent
gpg-agent --daemon --homedir ./data/gpg
# Then retry in the app
```

### "No GPG keys found"

```bash
gpg --list-secret-keys
# If empty, generate one (see GPG Setup above)
```

### Permission issues

```bash
chmod 700 data/gpg
chmod 600 data/gpg/*
```

### Debug mode

```bash
export VECTOR_PASS_DEBUG=1
python main.py
```

## Security Model

### What Vector-Pass protects against
- **Network interception** -- there is no network activity to intercept
- **Remote compromise of password vault** -- encrypted at rest with two layers
- **Credential stuffing** -- breach detection catches reused passwords
- **Weak password generation** -- enforces character variety and length

### What it does NOT protect against
- Keyloggers or other malware on your machine
- Compromised firmware/BIOS
- Physical access + rubber hose
- A sufficiently motivated state actor with access to your hardware

If your threat model includes the last two, you have bigger problems than password management.

## Security Hardening

For the particularly cautious:

```bash
# Clear shell history after sensitive ops
history -c

# Secure-delete temp files
shred -u temp_file.txt

# Drop filesystem caches (Linux)
sudo sync && sudo echo 3 > /proc/sys/vm/drop_caches
```

Consider:
- Running on an air-gapped machine for password generation
- Storing vault files on an encrypted USB
- Using hardware RNG if available
- Keeping vault backups encrypted with a different key

## License

This project is licensed under the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).

---

*Your passwords belong to you. Keep it that way.*
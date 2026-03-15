import os
import json
import base64
import getpass
from datetime import datetime
from typing import Dict, List, Optional, Any
import gnupg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class DualLayerEncryption:
    def __init__(self, gpg_home: str = None):
        try:
            
            if gpg_home is None:
                gpg_home = os.path.join(os.getcwd(), "data", "gpg")
                os.makedirs(gpg_home, exist_ok=True)
                os.chmod(gpg_home, 0o700)  
            
            self.gpg = gnupg.GPG(gnupghome=gpg_home, options=['--pinentry-mode', 'loopback'])
            
        except Exception as e:
            raise Exception(f"Failed to initialize GPG: {e}")
    
    def derive_aes_key(self, password: str, salt: bytes) -> bytes:
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return base64.urlsafe_b64encode(key)
    
    def aes_encrypt(self, data: str, password: str) -> Dict[str, str]:
        
        try:
            
            salt = os.urandom(32)
            
            
            key = self.derive_aes_key(password, salt)
            fernet = Fernet(key)
            
            encrypted_data = fernet.encrypt(data.encode('utf-8'))
            
            return {
                'encrypted_data': base64.urlsafe_b64encode(encrypted_data).decode('ascii'),
                'salt': base64.urlsafe_b64encode(salt).decode('ascii')
            }
        except Exception as e:
            raise Exception(f"AES encryption failed: {e}")
    
    def aes_decrypt(self, encrypted_package: Dict[str, str], password: str) -> str:
        try:
            salt = base64.urlsafe_b64decode(encrypted_package['salt'].encode('ascii'))
            encrypted_data = base64.urlsafe_b64decode(encrypted_package['encrypted_data'].encode('ascii'))
            
            key = self.derive_aes_key(password, salt)
            fernet = Fernet(key)
            
            decrypted_data = fernet.decrypt(encrypted_data)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise Exception(f"AES decryption failed: {e}")
    
    def setup_gpg_key(self, name: str, email: str, passphrase: str) -> str:
        """
        Generate a new GPG key for encryption.

        Troubleshooting GPG key generation issues:
        1. If you get "agent_genkey failed: No such file or directory" errors:
           - Kill conflicting GPG agent processes: ps aux | grep gpg-agent
           - Restart clean GPG agent: gpg-agent --daemon --homedir [project_gpg_directory]
        2. Ensure proper permissions on GPG directory (should be 700)
        3. Check that GPG is properly installed and accessible

        Args:
            name (str): User's real name
            email (str): User's email address
            passphrase (str): Passphrase for the GPG key

        Returns:
            str: Fingerprint of the generated key

        Raises:
            Exception: If key generation fails with detailed error information
        """
        try:
            print("Generating GPG key (this may take a moment)...")

            input_data = self.gpg.gen_key_input(
                name_real=name,
                name_email=email,
                passphrase=passphrase,
                key_type="RSA",
                key_length=4096
            )

            key = self.gpg.gen_key(input_data)

            # Better error checking with detailed GPG error messages
            if not key:
                raise Exception("GPG key generation returned None")

            # Check if key generation was successful by verifying fingerprint
            if not hasattr(key, 'fingerprint') or not key.fingerprint:
                error_msg = "GPG key generation failed - no fingerprint generated"
                # Include GPG stderr output if available for better diagnostics
                if hasattr(key, 'stderr') and key.stderr:
                    error_msg += f": {key.stderr.strip()}"
                elif hasattr(key, 'status'):
                    error_msg += f" (status: {key.status})"
                raise Exception(error_msg)

            # Check for any error messages even with successful fingerprint
            if hasattr(key, 'stderr') and key.stderr and "error" in key.stderr.lower():
                print(f"Warning during key generation: {key.stderr.strip()}")

            print(f"[+] GPG key created successfully: {key.fingerprint}")
            return key.fingerprint
        except Exception as e:
            # Preserve original exception but add context
            raise Exception(f"GPG key setup failed: {str(e)}")
    
    def get_gpg_keys(self) -> List[Dict[str, str]]:
        try:
            public_keys = self.gpg.list_keys()
            private_keys = self.gpg.list_keys(True)
            
            keys = []
            for key in private_keys:
                keys.append({
                    'fingerprint': key['fingerprint'],
                    'uid': key['uids'][0] if key['uids'] else 'Unknown',
                    'type': 'private'
                })
            
            for key in public_keys:
                if not any(k['fingerprint'] == key['fingerprint'] for k in keys):
                    keys.append({
                        'fingerprint': key['fingerprint'],
                        'uid': key['uids'][0] if key['uids'] else 'Unknown',
                        'type': 'public'
                    })
            
            return keys
        except Exception as e:
            raise Exception(f"Failed to get GPG keys: {e}")
    
    def gpg_encrypt(self, data: str, recipient_fingerprint: str) -> str:
        try:
           
            data_bytes = data.encode('utf-8')
            
            encrypted_data = self.gpg.encrypt(
                data_bytes, 
                recipient_fingerprint, 
                always_trust=True,
                armor=False,  
                passphrase=None  
            )
            
            if not encrypted_data.ok:
                raise Exception(f"GPG encryption failed: {encrypted_data.stderr}")
            
            
            return base64.b64encode(encrypted_data.data).decode('ascii')
        except Exception as e:
            raise Exception(f"GPG encryption error: {e}")
    
    def gpg_decrypt(self, encrypted_data_b64: str, passphrase: str) -> str:
        """Second layer: GPG decryption - FIXED with proper passphrase handling"""
        try:
            
            encrypted_data = base64.b64decode(encrypted_data_b64.encode('ascii'))
            
           
            decrypted_data = self.gpg.decrypt(
                encrypted_data, 
                passphrase=passphrase,
                always_trust=True
            )
            
            if not decrypted_data.ok:
             
                error_msg = f"GPG decryption failed: {decrypted_data.stderr}"
                if "No secret key" in decrypted_data.stderr:
                    error_msg += "\nMake sure you're using the correct GPG key and passphrase."
                raise Exception(error_msg)
            

            return decrypted_data.data.decode('utf-8')
        except Exception as e:
            raise Exception(f"GPG decryption error: {e}")
    
    def dual_encrypt(self, data: str, aes_password: str, gpg_recipient: str) -> str:
        """Dual-layer encryption: AES then GPG"""
        try:

            aes_encrypted = self.aes_encrypt(data, aes_password)
            aes_json = json.dumps(aes_encrypted)
            

            gpg_encrypted = self.gpg_encrypt(aes_json, gpg_recipient)
            return gpg_encrypted
        except Exception as e:
            raise Exception(f"Dual encryption failed: {e}")
    
    def dual_decrypt(self, encrypted_data: str, aes_password: str, gpg_passphrase: str) -> str:
        """Dual-layer decryption: GPG then AES"""
        try:

            gpg_decrypted = self.gpg_decrypt(encrypted_data, gpg_passphrase)
            aes_package = json.loads(gpg_decrypted)
            

            return self.aes_decrypt(aes_package, aes_password)
        except Exception as e:
            raise Exception(f"Dual decryption failed: {e}")


class PasswordEntry:
    
    def __init__(self, service: str, username: str, password: str, 
                 url: str = "", notes: str = "", tags: List[str] = None):
        self.service = service
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.tags = tags or []
        self.created = datetime.now().isoformat()
        self.modified = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'service': self.service,
            'username': self.username,
            'password': self.password,
            'url': self.url,
            'notes': self.notes,
            'tags': self.tags,
            'created': self.created,
            'modified': self.modified
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PasswordEntry':

        entry = cls(
            service=data['service'],
            username=data['username'],
            password=data['password'],
            url=data.get('url', ''),
            notes=data.get('notes', ''),
            tags=data.get('tags', [])
        )
        entry.created = data.get('created', datetime.now().isoformat())
        entry.modified = data.get('modified', datetime.now().isoformat())
        return entry


class PasswordManager:
    def __init__(self, vault_dir: str = "data/vaults", gpg_home: str = None):
        self.vault_dir = vault_dir
        self.encryption = DualLayerEncryption(gpg_home)
        self.current_vault = None
        self.entries: Dict[str, PasswordEntry] = {}
        self.metadata = {}
        self.loaded = False
        
        # Create directories if they don't exist
        os.makedirs(vault_dir, exist_ok=True)
    
    def list_vaults(self) -> List[str]:

        vaults = []
        if os.path.exists(self.vault_dir):
            for filename in os.listdir(self.vault_dir):
                if filename.endswith('.vault'):
                    vaults.append(filename[:-6])  # Remove .vault extension
        return vaults
    
    def create_vault(self, vault_name: str, aes_password: str, 
                    gpg_recipient: str = None, setup_new_gpg: bool = False) -> bool:

        try:
            # Check if vault already exists
            vault_path = os.path.join(self.vault_dir, f"{vault_name}.vault")
            if os.path.exists(vault_path):
                print(f"Vault '{vault_name}' already exists!")
                return False
            

            if setup_new_gpg:
                print("\n--- Setting up new GPG key ---")
                name = input("Enter your name: ")
                email = input("Enter your email: ")
                gpg_passphrase = getpass.getpass("Set GPG key passphrase: ")
                confirm_passphrase = getpass.getpass("Confirm GPG passphrase: ")
                
                if gpg_passphrase != confirm_passphrase:
                    print("GPG passphrases don't match!")
                    return False
                
                gpg_recipient = self.encryption.setup_gpg_key(name, email, gpg_passphrase)
                print(f"[*] Remember your GPG passphrase: You'll need it to unlock this vault!")
            
            if not gpg_recipient:
                keys = self.encryption.get_gpg_keys()
                if not keys:
                    print("No GPG keys found! Please setup a GPG key first.")
                    return False
                gpg_recipient = keys[0]['fingerprint']
                print(f"Using GPG key: {keys[0]['uid']}")

            initial_data = {
                'metadata': {
                    'vault_name': vault_name,
                    'created': datetime.now().isoformat(),
                    'version': '1.0',
                    'gpg_recipient': gpg_recipient,
                    'entry_count': 0
                },
                'entries': {}
            }
            
     
            encrypted_data = self.encryption.dual_encrypt(
                json.dumps(initial_data), 
                aes_password, 
                gpg_recipient
            )
            
    
            with open(vault_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
            
            self.current_vault = vault_name
            print(f"[+] Vault '{vault_name}' created successfully!")
            return True
            
        except Exception as e:
            print(f"[-] Failed to create vault: {e}")
            return False
    
    def load_vault(self, vault_name: str, aes_password: str, gpg_passphrase: str = None) -> bool:

        try:
            vault_path = os.path.join(self.vault_dir, f"{vault_name}.vault")
            if not os.path.exists(vault_path):
                print(f"Vault '{vault_name}' not found!")
                return False

            if gpg_passphrase is None:
                print(f"\n[*] GPG Key required for vault '{vault_name}'")
                gpg_passphrase = getpass.getpass("Enter GPG key passphrase: ")
            

            with open(vault_path, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()

            decrypted_data = self.encryption.dual_decrypt(
                encrypted_data, aes_password, gpg_passphrase
            )
            
        
            vault_data = json.loads(decrypted_data)
            self.metadata = vault_data.get('metadata', {})
            
           
            self.entries = {}
            for entry_id, entry_data in vault_data.get('entries', {}).items():
                self.entries[entry_id] = PasswordEntry.from_dict(entry_data)
            
            self.current_vault = vault_name
            self.loaded = True
            
            print(f"[+] Vault '{vault_name}' loaded successfully!")
            print(f"    Entries loaded: {len(self.entries)}")
            return True
            
        except Exception as e:
            print(f"[-] Failed to load vault: {e}")
            return False
    
    def save_vault(self, aes_password: str, gpg_passphrase: str = None) -> bool:
        """Encrypt and save the current vault"""
        if not self.loaded:
            print("No vault loaded!")
            return False
        
        try:
            vault_path = os.path.join(self.vault_dir, f"{self.current_vault}.vault")
            
        
            vault_data = {
                'metadata': {
                    **self.metadata,
                    'modified': datetime.now().isoformat(),
                    'entry_count': len(self.entries)
                },
                'entries': {entry_id: entry.to_dict() for entry_id, entry in self.entries.items()}
            }
            
        
            gpg_recipient = self.metadata.get('gpg_recipient')
            if not gpg_recipient:
                print("No GPG recipient found in vault metadata!")
                return False
            

            if gpg_passphrase is None:
                print(f"\n[*] GPG Key required to save vault '{self.current_vault}'")
                gpg_passphrase = getpass.getpass("Enter GPG key passphrase: ")

            encrypted_data = self.encryption.dual_encrypt(
                json.dumps(vault_data), 
                aes_password, 
                gpg_recipient
            )
            
        
            with open(vault_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
            
            print(f"[+] Vault '{self.current_vault}' saved successfully!")
            return True
            
        except Exception as e:
            print(f"[-] Failed to save vault: {e}")
            return False
    
    def add_entry(self, service: str, username: str, password: str, 
                  url: str = "", notes: str = "", tags: List[str] = None) -> bool:

        if not self.loaded:
            print("No vault loaded!")
            return False
        
        try:
            entry_id = f"{service.lower()}_{username.lower()}"
            
            if entry_id in self.entries:
                overwrite = input(f"Entry for {service}/{username} already exists. Overwrite? (y/n): ")
                if overwrite.lower() != 'y':
                    return False
            
            self.entries[entry_id] = PasswordEntry(
                service=service,
                username=username,
                password=password,
                url=url,
                notes=notes,
                tags=tags or []
            )
            
            print(f"[+] Entry added for {service}")
            return True
            
        except Exception as e:
            print(f"[-] Failed to add entry: {e}")
            return False
    
    def get_entry(self, service: str, username: str) -> Optional[PasswordEntry]:

        if not self.loaded:
            return None
        
        entry_id = f"{service.lower()}_{username.lower()}"
        return self.entries.get(entry_id)
    
    def list_entries(self, show_passwords: bool = False) -> List[Dict]:

        if not self.loaded:
            return []
        
        entries_list = []
        for entry in self.entries.values():
            entry_info = {
                'service': entry.service,
                'username': entry.username,
                'url': entry.url,
                'modified': entry.modified
            }
            if show_passwords:
                entry_info['password'] = entry.password
            entries_list.append(entry_info)
        
        return entries_list
    
    def search_entries(self, query: str) -> List[Dict]:

        if not self.loaded:
            return []
        
        results = []
        query_lower = query.lower()
        
        for entry in self.entries.values():
            if (query_lower in entry.service.lower() or 
                query_lower in entry.username.lower() or
                any(query_lower in tag.lower() for tag in entry.tags)):
                
                results.append({
                    'service': entry.service,
                    'username': entry.username,
                    'url': entry.url,
                    'modified': entry.modified
                })
        
        return results
    
    def delete_entry(self, service: str, username: str) -> bool:

        if not self.loaded:
            print("No vault loaded!")
            return False
        
        entry_id = f"{service.lower()}_{username.lower()}"
        if entry_id in self.entries:
            del self.entries[entry_id]
            print(f"[+] Entry deleted for {service}/{username}")
            return True
        else:
            print(f"Entry not found for {service}/{username}")
            return False
    
    def export_entries(self, filename: str, export_password: str = None) -> bool:

        if not self.loaded:
            print("No vault loaded!")
            return False
        
        try:
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'vault_name': self.current_vault,
                'entries': [entry.to_dict() for entry in self.entries.values()]
            }
            
            if export_password:

                encrypted = self.encryption.aes_encrypt(json.dumps(export_data), export_password)
                export_data = encrypted
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"[+] Entries exported to {filename}")
            return True
            
        except Exception as e:
            print(f"[-] Export failed: {e}")
            return False
    
    def import_entries(self, filename: str, import_password: str = None) -> bool:

        if not self.loaded:
            print("No vault loaded!")
            return False
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            

            if import_password:
                import_data = json.loads(self.encryption.aes_decrypt(import_data, import_password))
            
            imported_count = 0
            for entry_data in import_data.get('entries', []):
                entry = PasswordEntry.from_dict(entry_data)
                entry_id = f"{entry.service.lower()}_{entry.username.lower()}"
                self.entries[entry_id] = entry
                imported_count += 1
            
            print(f"[+] Imported {imported_count} entries")
            return True
            
        except Exception as e:
            print(f"[-] Import failed: {e}")
            return False
    
    def get_vault_info(self) -> Dict[str, Any]:
   
        if not self.loaded:
            return {}
        
        return {
            'vault_name': self.current_vault,
            'entry_count': len(self.entries),
            'created': self.metadata.get('created'),
            'modified': self.metadata.get('modified'),
            'gpg_recipient': self.metadata.get('gpg_recipient')
        }




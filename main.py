#!/usr/bin/env python3


import os
import sys
import argparse
import getpass
from typing import Optional, List, Dict

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from password_generator import PasswordGenerator
    from password_strength import PasswordStrengthChecker
    from password_manager import PasswordManager, PasswordEntry
    # Import bloom_filter to ensure it's available
    try:
        from bloom_filter import BloomFilter
    except ImportError:
        pass  # Bloom filter is optional
except ImportError as e:
    print(f"[-] Error importing modules: {e}")
    print("Please ensure all required modules are in the 'src' directory")
    sys.exit(1)


class SecurePasswordManager:
   
    
    def __init__(self):
        self.generator = PasswordGenerator()
        self.strength_checker = PasswordStrengthChecker()
        self.manager = PasswordManager()
        self.current_vault_password = None
        self.current_gpg_passphrase = None
    
    def print_banner(self):
        banner = """
        Vector-Pass
        =============================
        * Generate Strong Passwords
        * Check Password Strength  
        * Secure Encrypted Storage
        * Dual-Layer Encryption (AES + GPG)
        =============================
        """
        print(banner)
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def press_enter_to_continue(self):
        """Wait for user to press Enter"""
        input("\nPress Enter to continue...")
    
    def generate_password_interactive(self):
        """Interactive password generation flow"""
        print("\n" + "="*50)
        print("PASSWORD GENERATOR")
        print("="*50)
        
        try:
            length = int(input("Enter password length (default 16): ") or "16")
            
            if length < 8:
                print("[-] Password length should be at least 8 characters!")
                return
            
            print("\nGenerating secure password...")
            password = self.generator.pwd_gen(length)
            
            if password:
                
                strength = self.strength_checker.check_strength(password)
                
                print(f"\n[+] Generated Password: {password}")
                print(f"    Strength: {strength['level']} ({strength['score']}/100)")
                print(f"    Entropy: {strength['entropy']} bits")
                print(f"    Crack Time: {strength['crack_time']}")
                
                if strength['leaked']:
                    print("[!] Warning: Similar passwords found in data breaches!")
                
                
                copy = input("\nCopy to clipboard? (y/n): ").lower()
                if copy == 'y':
                    try:
                        import pyperclip
                        pyperclip.copy(password)
                        print("[+] Password copied to clipboard!")
                    except ImportError:
                        print("[-] pyperclip not installed. Install with: pip install pyperclip")
                
                
                if self.manager.loaded:
                    save = input("\nSave to password manager? (y/n): ").lower()
                    if save == 'y':
                        self.save_password_to_vault(password)
            
        except ValueError:
            print("[-] Please enter a valid number!")
        except Exception as e:
            print(f"[-] Error generating password: {e}")
    
    def save_password_to_vault(self, password: str):
        
        if not self.manager.loaded:
            print("[-] No vault loaded!")
            return
        
        print("\nSave Password to Vault")
        service = input("Service (e.g., Gmail, Facebook): ")
        username = input("Username/Email: ")
        url = input("URL (optional): ")
        notes = input("Notes (optional): ")
        
        if self.manager.add_entry(service, username, password, url, notes):
            
            if self.manager.save_vault(self.current_vault_password, self.current_gpg_passphrase):
                print("[+] Password saved to vault!")
            else:
                print("[-] Failed to save vault!")
    
    def check_strength_interactive(self):
       
        print("\n" + "="*50)
        print("PASSWORD STRENGTH CHECKER")
        print("="*50)
        
        password = getpass.getpass("Enter password to check: ")
        
        if not password:
            print("[-] Password cannot be empty!")
            return
        
        print("\nAnalyzing password...")
        strength = self.strength_checker.check_strength(password)
        
        print(f"\nSTRENGTH ANALYSIS")
        print(f"Score: {strength['score']}/100 - {strength['level']}")
        print(f"Length: {strength['length']} characters")
        print(f"Entropy: {strength['entropy']} bits")
        print(f"Estimated Crack Time: {strength['crack_time']}")
        print(f"Found in Data Breaches: {'YES' if strength['leaked'] else 'No'}")
        
        print(f"\nCHARACTER VARIETY")
        checks = strength['checks']
        print(f"Uppercase Letters: {'[+]' if checks['has_uppercase'] else '[-]'}")
        print(f"Lowercase Letters: {'[+]' if checks['has_lowercase'] else '[-]'}")
        print(f"Numbers: {'[+]' if checks['has_digits'] else '[-]'}")
        print(f"Special Characters: {'[+]' if checks['has_special'] else '[-]'}")
        print(f"No Repeated Chars: {'[+]' if checks['no_repeats'] else '[-]'}")
        print(f"No Sequences: {'[+]' if checks['no_sequences'] else '[-]'}")
        print(f"No Common Patterns: {'[+]' if checks['no_common_patterns'] else '[-]'}")
        
        print(f"\nRECOMMENDATIONS")
        for feedback in strength['feedback']:
            print(f"  {feedback}")
        
        if strength['leaked']:
            print(f"\n[!!] CRITICAL: This password has been compromised in data breaches!")
            print("[!!] DO NOT USE THIS PASSWORD!")
    
    def password_manager_menu(self):
        
        while True:
            print("\n" + "="*50)
            print("PASSWORD MANAGER")
            print("="*50)
            print("1. Create New Vault")
            print("2. Load Existing Vault")
            print("3. List Available Vaults")
            print("4. Manage GPG Keys")
            print("5. Back to Main Menu")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.create_vault_flow()
            elif choice == '2':
                self.load_vault_flow()
            elif choice == '3':
                self.list_vaults()
            elif choice == '4':
                self.manage_gpg_keys()
            elif choice == '5':
                break
            else:
                print("[-] Invalid option!")
    
    def create_vault_flow(self):
        
        print("\n" + "="*50)
        print("CREATE NEW VAULT")
        print("="*50)
        
        vault_name = input("Enter vault name: ").strip()
        if not vault_name:
            print("[-] Vault name cannot be empty!")
            return
        
       
        aes_password = getpass.getpass("Set AES encryption password: ")
        confirm_password = getpass.getpass("Confirm AES password: ")
        
        if aes_password != confirm_password:
            print("[-] Passwords don't match!")
            return
        
       
        setup_gpg = input("Setup new GPG key? (y/n): ").lower() == 'y'
        
        if self.manager.create_vault(vault_name, aes_password, setup_new_gpg=setup_gpg):
            print(f"\n[+] Vault '{vault_name}' created successfully!")
            
            
            if setup_gpg:
                gpg_passphrase = getpass.getpass("Enter GPG passphrase to unlock vault: ")
                if self.manager.load_vault(vault_name, aes_password, gpg_passphrase):
                    self.current_vault_password = aes_password
                    self.current_gpg_passphrase = gpg_passphrase
                    self.vault_operations_menu()
            else:
                if self.manager.load_vault(vault_name, aes_password):
                    self.current_vault_password = aes_password
                    self.vault_operations_menu()
    
    def load_vault_flow(self):
       
        vaults = self.manager.list_vaults()
        
        if not vaults:
            print("[-] No vaults found! Create one first.")
            return
        
        print("\nAvailable Vaults:")
        for i, vault in enumerate(vaults, 1):
            print(f"{i}. {vault}")
        
        try:
            choice = int(input("\nSelect vault: ")) - 1
            vault_name = vaults[choice]
        except (ValueError, IndexError):
            print("[-] Invalid selection!")
            return
        
        aes_password = getpass.getpass("Enter AES password: ")
        
       
        if not self.manager.load_vault(vault_name, aes_password):
           
            print("\n[*] GPG decryption failed. Please provide GPG passphrase.")
            gpg_passphrase = getpass.getpass("Enter GPG key passphrase: ")
            if self.manager.load_vault(vault_name, aes_password, gpg_passphrase):
                self.current_vault_password = aes_password
                self.current_gpg_passphrase = gpg_passphrase
                self.vault_operations_menu()
            else:
                print("[-] Failed to load vault!")
        else:
            self.current_vault_password = aes_password
            self.vault_operations_menu()
    
    def list_vaults(self):
   
        vaults = self.manager.list_vaults()
        
        if not vaults:
            print("[-] No vaults found!")
            return
        
        print("\nAvailable Vaults:")
        for i, vault in enumerate(vaults, 1):
            print(f"{i}. {vault}")
        print(f"\nTotal: {len(vaults)} vault(s)")
    
    def manage_gpg_keys(self):
        
        print("\n" + "="*50)
        print("GPG KEY MANAGEMENT")
        print("="*50)
        print("1. List GPG Keys")
        print("2. Create New GPG Key")
        print("3. Back")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            try:
                keys = self.manager.encryption.get_gpg_keys()
                if not keys:
                    print("[-] No GPG keys found.")
                else:
                    print("\nAvailable GPG Keys:")
                    for key in keys:
                        print(f"• {key['uid']} ({key['fingerprint'][-8:]}) - {key['type']}")
            except Exception as e:
                print(f"[-] Error listing keys: {e}")
        
        elif choice == '2':
            name = input("Enter your name: ")
            email = input("Enter your email: ")
            passphrase = getpass.getpass("Set GPG key passphrase: ")
            confirm = getpass.getpass("Confirm passphrase: ")
            
            if passphrase != confirm:
                print("[-] Passphrases don't match!")
                return
            
            try:
                fingerprint = self.manager.encryption.setup_gpg_key(name, email, passphrase)
                print(f"[+] GPG key created: {fingerprint}")
            except Exception as e:
                print(f"[-] Failed to create GPG key: {e}")
    
    def vault_operations_menu(self):
        """Operations menu for loaded vault"""
        while True:
            vault_info = self.manager.get_vault_info()
            vault_name = vault_info.get('vault_name', 'Unknown')
            entry_count = vault_info.get('entry_count', 0)
            
            print("\n" + "="*50)
            print(f"VAULT: {vault_name} ({entry_count} entries)")
            print("="*50)
            print("1. Add Password Entry")
            print("2. List All Entries")
            print("3. Search Entries")
            print("4. Get Password")
            print("5. Delete Entry")
            print("6. Vault Information")
            print("7. Generate & Save Password")
            print("8. Save Vault")
            print("9. Back to Password Manager")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.add_entry_flow()
            elif choice == '2':
                self.list_entries_flow()
            elif choice == '3':
                self.search_entries_flow()
            elif choice == '4':
                self.get_password_flow()
            elif choice == '5':
                self.delete_entry_flow()
            elif choice == '6':
                self.vault_info_flow()
            elif choice == '7':
                self.generate_and_save_flow()
            elif choice == '8':
                if self.manager.save_vault(self.current_vault_password, self.current_gpg_passphrase):
                    print("[+] Vault saved successfully!")
                else:
                    print("[-] Failed to save vault!")
            elif choice == '9':
                if self.manager.save_vault(self.current_vault_password, self.current_gpg_passphrase):
                    print("[+] Vault saved successfully!")
                break
            else:
                print("[-] Invalid option!")
    
    def add_entry_flow(self):
        
        print("\n" + "="*50)
        print("ADD PASSWORD ENTRY")
        print("="*50)
        
        service = input("Service: ")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        url = input("URL (optional): ")
        notes = input("Notes (optional): ")
        
        if not service or not username or not password:
            print("[-] Service, username, and password are required!")
            return
        
        if self.manager.add_entry(service, username, password, url, notes):
            print("[+] Entry added successfully!")
        else:
            print("[-] Failed to add entry!")
    
    def list_entries_flow(self):
        
        entries = self.manager.list_entries()
        
        if not entries:
            print("[-] No entries found.")
            return
        
        print(f"\nEntries ({len(entries)}):")
        print("-" * 60)
        for i, entry in enumerate(entries, 1):
            print(f"{i}. {entry['service']} - {entry['username']}")
            if entry['url']:
                print(f"   URL: {entry['url']}")
            print(f"   Last modified: {entry['modified'][:10]}")
            print()
    
    def search_entries_flow(self):
        
        query = input("Search (service, username, or tags): ")
        
        if not query:
            print("[-] Please enter a search term!")
            return
        
        results = self.manager.search_entries(query)
        
        if not results:
            print("[-] No matches found.")
            return
        
        print(f"\nSearch Results ({len(results)}):")
        print("-" * 60)
        for i, entry in enumerate(results, 1):
            print(f"{i}. {entry['service']} - {entry['username']}")
            if entry['url']:
                print(f"   URL: {entry['url']}")
    
    def get_password_flow(self):
        
        service = input("Service: ")
        username = input("Username: ")
        
        entry = self.manager.get_entry(service, username)
        if entry:
            print(f"\nENTRY DETAILS")
            print(f"Service: {entry.service}")
            print(f"Username: {entry.username}")
            print(f"Password: {entry.password}")
            if entry.url:
                print(f"URL: {entry.url}")
            if entry.notes:
                print(f"Notes: {entry.notes}")
            print(f"Created: {entry.created[:10]}")
            print(f"Modified: {entry.modified[:10]}")
            
            # Copy to clipboard option
            copy = input("\nCopy password to clipboard? (y/n): ").lower()
            if copy == 'y':
                try:
                    import pyperclip
                    pyperclip.copy(entry.password)
                    print("[+] Password copied to clipboard!")
                except ImportError:
                    print("[-] pyperclip not installed")
        else:
            print("[-] Entry not found!")
    
    def delete_entry_flow(self):
        
        service = input("Service: ")
        username = input("Username: ")
        
        confirm = input(f"Are you sure you want to delete entry for {service}/{username}? (y/n): ")
        if confirm.lower() == 'y':
            if self.manager.delete_entry(service, username):
                print("[+] Entry deleted successfully!")
            else:
                print("[-] Failed to delete entry!")
    
    def vault_info_flow(self):
        """Display vault information"""
        info = self.manager.get_vault_info()
        
        if not info:
            print("[-] No vault information available!")
            return
        
        print(f"\nVAULT INFORMATION")
        print(f"Name: {info.get('vault_name', 'Unknown')}")
        print(f"Entries: {info.get('entry_count', 0)}")
        print(f"Created: {info.get('created', 'Unknown')}")
        print(f"Modified: {info.get('modified', 'Unknown')}")
        print(f"GPG Recipient: {info.get('gpg_recipient', 'Not set')}")
    
    def generate_and_save_flow(self):
       
        print("\n" + "="*50)
        print("GENERATE & SAVE PASSWORD")
        print("="*50)
        
        try:
            length = int(input("Enter password length (default 16): ") or "16")
            
            if length < 8:
                print("[-] Password length should be at least 8 characters!")
                return
            
            print("\nGenerating secure password...")
            password = self.generator.pwd_gen(length)
            
            if password:
                print(f"\n[+] Generated Password: {password}")
                
             
                self.save_password_to_vault(password)
            
        except ValueError:
            print("[-] Please enter a valid number!")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def main_menu(self):
       
        while True:
            self.clear_screen()
            self.print_banner()
            
            print("MAIN MENU:")
            print("1. Generate Password")
            print("2. Check Password Strength")
            print("3. Password Manager")
            print("4. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.generate_password_interactive()
                self.press_enter_to_continue()
            elif choice == '2':
                self.check_strength_interactive()
                self.press_enter_to_continue()
            elif choice == '3':
                self.password_manager_menu()
            elif choice == '4':
                print("\nThank you for using Vector-Pass.")
                print("Stay secure.")
                break
            else:
                print("[-] Invalid option!")
                self.press_enter_to_continue()


def main():
    """Main entry point"""
    try:
        app = SecurePasswordManager()
        app.main_menu()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye.")
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        print("Please check your installation and try again.")


if __name__ == "__main__":
    
    os.makedirs("data/vaults", exist_ok=True)
    os.makedirs("data/leaked_passwords", exist_ok=True)
    
    if not os.listdir("data/leaked_passwords"):
        print("[!] No leaked password wordlists found in data/leaked_passwords/")    
    main()
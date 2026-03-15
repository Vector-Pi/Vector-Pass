import re
import math
from typing import Dict, List, Tuple
import os

# Import the BloomFilter class
try:
    from bloom_filter import BloomFilter
    BLOOM_FILTER_AVAILABLE = True
except ImportError:
    BLOOM_FILTER_AVAILABLE = False
    print("Warning: Bloom filter not available. Using fallback method.")


class PasswordStrengthChecker:
    def __init__(self, wordlist_dir: str = "data/leaked_passwords"):
        self.wordlist_dir = wordlist_dir

        # Try to load bloom filter, fall back to set if not available
        if BLOOM_FILTER_AVAILABLE:
            self.leaked_passwords = self._load_leaked_passwords_bloom()
        else:
            self.leaked_passwords = self._load_leaked_passwords()

        self.common_patterns = [
            '123456', 'password', 'qwerty', 'abc123', 'letmein', 'welcome',
            'monkey', 'dragon', 'master', 'hello', 'freedom', 'whatever'
        ]

    def _load_leaked_passwords_bloom(self):
        """Load leaked passwords using Bloom filter for memory efficiency"""
        bloom_file = os.path.join(self.wordlist_dir, "bloom_filter.dat")

        try:
            # Try to load existing bloom filter
            if os.path.exists(bloom_file):
                bf = BloomFilter.load(bloom_file)
                print(f"Loaded Bloom filter with {bf.get_stats()['memory_usage_bytes'] / (1024*1024):.1f} MB memory usage")
                return bf
            else:
                # Build new bloom filter from wordlists
                print("Bloom filter not found, building from wordlists...")
                bf = BloomFilter(expected_items=50000000, false_positive_rate=0.01)

                # Load passwords from files
                try:
                    for filename in os.listdir(self.wordlist_dir):
                        if filename.endswith('.txt'):
                            filepath = os.path.join(self.wordlist_dir, filename)
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    password = line.strip()
                                    if password:
                                        bf.add(password)

                    # Save the bloom filter for future use
                    bf.save(bloom_file)
                    print(f"Built Bloom filter with {bf.get_stats()['memory_usage_bytes'] / (1024*1024):.1f} MB memory usage")
                    return bf

                except FileNotFoundError:
                    print("Warning: Leaked password directory not found")
                    return bf  # Return empty bloom filter

        except Exception as e:
            print(f"Error loading Bloom filter: {e}")
            print("Falling back to traditional set-based approach")
            return self._load_leaked_passwords()

    def _load_leaked_passwords(self) -> set:
        """Fallback method: Load leaked passwords into a set (high memory usage)"""
        leaked_set = set()
        try:
            for filename in os.listdir(self.wordlist_dir):
                if filename.endswith('.txt'):
                    with open(os.path.join(self.wordlist_dir, filename), 'r',
                             encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            leaked_set.add(line.strip().lower())
        except FileNotFoundError:
            print("Warning: Leaked password directory not found")
        return leaked_set

    def is_password_leaked(self, password: str) -> bool:
        """Check if password exists in leaked databases"""
        if BLOOM_FILTER_AVAILABLE and hasattr(self.leaked_passwords, 'check'):
            # Use Bloom filter check
            return self.leaked_passwords.check(password)
        else:
            # Fallback to set membership
            return password.lower() in self.leaked_passwords
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy in bits
        Higher entropy = more secure
        """
        if not password:
            return 0
        
        char_pool = 0
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if has_upper:
            char_pool += 26
        if has_lower:
            char_pool += 26
        if has_digits:
            char_pool += 10
        if has_special:

            char_pool += 32
        
     
        if char_pool == 0:
            char_pool = 26  
        
        
        entropy = len(password) * math.log2(char_pool)
        return round(entropy, 2)
    
    def check_character_variety(self, password: str) -> Dict[str, bool]:
        """Check what types of characters are present"""
        return {
            'length_adequate': len(password) >= 8,
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password),
            'no_repeats': len(password) == len(set(password)),  # No repeated chars
            'no_sequences': not self._has_sequences(password),
            'no_common_patterns': not self._has_common_patterns(password)
        }
    
    def _has_sequences(self, password: str) -> bool:
        """Check for common sequences"""
        lower_pass = password.lower()
        
        
        sequences = [
            'qwerty', 'asdfgh', 'zxcvbn', '123456', 'abcdef',
            '987654', '654321'
        ]
        
        for seq in sequences:
            if seq in lower_pass:
                return True
        
      
        for i in range(len(password) - 2):
         
            if (password[i:i+3].isdigit() and 
                abs(ord(password[i]) - ord(password[i+1])) == 1 and
                abs(ord(password[i+1]) - ord(password[i+2])) == 1):
                return True
        
        return False
    
    def _has_common_patterns(self, password: str) -> bool:
        """Check for common insecure patterns"""
        lower_password = password.lower()
        
        
        for pattern in self.common_patterns:
            if pattern in lower_password:
                return True
        
      
        if re.search(r'(.)\1{2,}', password):  
            return True
        
       
        common_subs = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7']
        }
        
       
        leet_patterns = [
            r'p[@4]ssw[o0]rd', r'[a@]dm[i1]n', r'w[e3]lc[o0]me',
            r'l[e3]tm[e3][i1]n', r'm[o0]n[k1]ey'
        ]
        
        for pattern in leet_patterns:
            if re.search(pattern, lower_password):
                return True
        
        return False
    
    def estimate_crack_time(self, entropy: float) -> str:
        
        guesses_per_second = 10**12
        possible_combinations = 2 ** entropy
        
        seconds = possible_combinations / guesses_per_second
        
        if seconds < 60:
            return "Instantly"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
        elif seconds < 31536000:  # 1 year
            return f"{int(seconds/86400)} days"
        elif seconds < 3153600000:  # 100 years
            return f"{int(seconds/31536000)} years"
        else:
            return "Centuries"
    
    def get_strength_score(self, password: str) -> int:
  
        if not password:
            return 0
        
        score = 0
        checks = self.check_character_variety(password)
        entropy = self.calculate_entropy(password)
        
    
        length_bonus = min(len(password) * 2, 30)
        score += length_bonus
        
  
        variety_points = 0
        if checks['has_uppercase']:
            variety_points += 8
        if checks['has_lowercase']:
            variety_points += 8
        if checks['has_digits']:
            variety_points += 8
        if checks['has_special']:
            variety_points += 8
        if checks['no_repeats']:
            variety_points += 4
        if checks['no_sequences']:
            variety_points += 4
        
        score += min(variety_points, 40)
        
     
        entropy_points = min(entropy / 2, 30) 
        score += entropy_points
        
   
        if self.is_password_leaked(password):
            score = max(0, score - 50)  
        
        if not checks['no_common_patterns']:
            score = max(0, score - 20)
        
        return min(int(score), 100)
    
    def get_strength_level(self, score: int) -> str:
        """Convert score to strength level"""
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Moderate"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"
    
    def check_strength(self, password: str) -> Dict:
      
        if not password:
            return {
                'score': 0,
                'level': 'Very Weak',
                'entropy': 0,
                'crack_time': 'Instantly',
                'leaked': False,
                'feedback': ['Password cannot be empty'],
                'checks': {}
            }
        
        score = self.get_strength_score(password)
        level = self.get_strength_level(score)
        entropy = self.calculate_entropy(password)
        crack_time = self.estimate_crack_time(entropy)
        leaked = self.is_password_leaked(password)
        checks = self.check_character_variety(password)
        
        feedback = self._generate_feedback(password, checks, leaked, score)
        
        return {
            'score': score,
            'level': level,
            'entropy': entropy,
            'crack_time': crack_time,
            'leaked': leaked,
            'feedback': feedback,
            'checks': checks,
            'length': len(password)
        }
    
    def _generate_feedback(self, password: str, checks: Dict, 
                          leaked: bool, score: int) -> List[str]:
        """Generate improvement suggestions"""
        feedback = []
        
    
        if len(password) < 8:
            feedback.append("[-] Password should be at least 8 characters long")
        elif len(password) < 12:
            feedback.append("[!] Consider using 12+ characters for better security")
        else:
            feedback.append("[+] Good password length")
        
        if not checks['has_uppercase']:
            feedback.append("[-] Add uppercase letters (A-Z)")
        else:
            feedback.append("[+] Contains uppercase letters")
        
        if not checks['has_lowercase']:
            feedback.append("[-] Add lowercase letters (a-z)")
        else:
            feedback.append("[+] Contains lowercase letters")
        
        if not checks['has_digits']:
            feedback.append("[-] Add numbers (0-9)")
        else:
            feedback.append("[+] Contains numbers")
        
        if not checks['has_special']:
            feedback.append("[-] Add special characters (!@#$% etc.)")
        else:
            feedback.append("[+] Contains special characters")
        
    
        if not checks['no_repeats']:
            feedback.append("[!] Avoid repeated characters")
        
        if not checks['no_sequences']:
            feedback.append("[-] Avoid keyboard sequences (qwerty, 12345)")
        
        if not checks['no_common_patterns']:
            feedback.append("[-] Avoid common words and patterns")
        
       
        if leaked:
            feedback.append("[!!] CRITICAL: This password has been found in data breaches!")
            feedback.append("[!!] DO NOT USE THIS PASSWORD!")
        
        
        if score < 40:
            feedback.append("Tip: Use a longer password with more character types")
        elif score < 60:
            feedback.append("Tip: Add special characters and avoid common patterns")
        elif score < 80:
            feedback.append("Tip: Consider making it longer and more random")
        else:
            feedback.append("[+] Excellent -- this is a strong password")
        
        return feedback
    
    def validate_password(self, password: str, min_score: int = 60) -> Tuple[bool, str]:
        """
        Simple validation - returns (is_valid, message)
        """
        strength = self.check_strength(password)
        
        if strength['leaked']:
            return False, "Password has been compromised in data breaches"
        
        if strength['score'] < min_score:
            return False, f"Password too weak (score: {strength['score']}/100)"
        
        return True, f"Password strength: {strength['level']}"


if __name__ == "__main__":
   
    checker = PasswordStrengthChecker()
    
   
    test_passwords = [
        "password123",
        "P@ssw0rd!",
        "weak",
        "StrongP@ss123!",
        "123456789",
        "qwertyuiop",
        "MySuperSecureP@ssw0rd!2024"
    ]
    
    print("Password Strength Analysis\n")
    print("=" * 60)
    
    for pwd in test_passwords:
        result = checker.check_strength(pwd)
        
        print(f"\nPassword: {pwd}")
        print(f"Strength: {result['level']} ({result['score']}/100)")
        print(f"Length: {result['length']} characters")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Estimated Crack Time: {result['crack_time']}")
        print(f"Leaked: {'YES' if result['leaked'] else 'No'}")
        
        print("\nFeedback:")
        for fb in result['feedback'][:3]:  
            print(f"  {fb}")
        
        print("-" * 40)
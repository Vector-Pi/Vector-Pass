import random
from typing import List, Dict


class PasswordGenerator:
    """A class to generate secure passwords with customizable options."""

    def __init__(self):
        """Initialize the password generator with default character sets."""
        self.uppercase_letters = [chr(x) for x in range(ord('A'), ord('Z')+1)]
        self.lowercase_letters = [chr(x) for x in range(ord('a'), ord('z')+1)]
        self.digits = [str(x) for x in range(10)]
        # Removed '•' character to prevent encoding issues
        self.special_characters = ['@','#', '!', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '<', '>', '?']

    def pwd_gen(self, length=16) -> str:
        """
        Generate a secure password with specified length.

        Args:
            length (int): Desired password length (default: 16)

        Returns:
            str: Generated password
        """
        if length < 6:
            raise ValueError("Password length should be at least 6 characters")

        # Combine all character sets
        all_chars = []
        all_chars.extend(self.uppercase_letters)
        all_chars.extend(self.lowercase_letters)
        all_chars.extend(self.digits)
        all_chars.extend(self.special_characters)
        random.shuffle(all_chars)

        # Initialize password with required character types
        password_chars = []

        # Ensure at least one character from each required type
        password_chars.append(random.choice(self.uppercase_letters))
        password_chars.append(random.choice(self.lowercase_letters))
        password_chars.append(random.choice(self.digits))
        password_chars.append(random.choice(self.special_characters))

        # Fill remaining length with random characters
        for _ in range(length - 4):
            password_chars.append(random.choice(all_chars))

        # Shuffle the password characters to avoid predictable patterns
        random.shuffle(password_chars)

        # Convert to string
        password = ''.join(password_chars)

        # Ensure we meet the exact length requirement
        if len(password) > length:
            password = password[:length]

        # Improve password strength without double printing
        password = self.improve_password_strength(password)

        return password

    @staticmethod
    def improve_password_strength(password: str) -> str:
        """
        Improve password strength by ensuring all character types are present.

        Args:
            password (str): Input password to improve

        Returns:
            str: Improved password
        """
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long!")

        # Character sets for improvement
        uppercase_letters = [chr(x) for x in range(ord('A'), ord('Z')+1)]
        lowercase_letters = [chr(x) for x in range(ord('a'), ord('z')+1)]
        digits = [str(x) for x in range(10)]
        special_characters = ['@','#', '!', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '<', '>', '?']

        # Check for character types
        uppercase_present = any(char.isupper() for char in password)
        lowercase_present = any(char.islower() for char in password)
        digit_present = any(char.isdigit() for char in password)
        special_present = any(char in special_characters for char in password)

        # Add missing character types
        improved_password = list(password)

        if not uppercase_present:
            improved_password.append(random.choice(uppercase_letters))
        if not lowercase_present:
            improved_password.append(random.choice(lowercase_letters))
        if not digit_present:
            improved_password.append(random.choice(digits))
        if not special_present:
            improved_password.append(random.choice(special_characters))

        # Remove duplicates while preserving order (instead of using set which breaks order)
        seen = set()
        result = []
        for char in improved_password:
            if char not in seen:
                seen.add(char)
                result.append(char)

        # Join characters back into a string
        return ''.join(result)


# For testing purposes when running directly
if __name__ == "__main__":
    generator = PasswordGenerator()
    length = int(input("Enter Required Length Of Characters: "))
    password = generator.pwd_gen(length)
    print("Your generated password:", password)
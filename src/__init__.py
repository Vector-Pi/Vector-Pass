"""
Vector-Pass - A comprehensive password management solution

This package provides:
- Secure password generation
- Password strength analysis
- Dual-layer encryption (AES + GPG)
- Secure encrypted vault storage
"""

__version__ = "1.0.0"
__author__ = "Vector-Pass Team"

# Expose the main classes for easy importing
from .password_generator import PasswordGenerator
from .password_strength import PasswordStrengthChecker
from .password_manager import PasswordManager, PasswordEntry
from .bloom_filter import BloomFilter

__all__ = [
    "PasswordGenerator",
    "PasswordStrengthChecker",
    "PasswordManager",
    "PasswordEntry",
    "BloomFilter"
]
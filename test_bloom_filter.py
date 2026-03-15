#!/usr/bin/env python3
"""
Test script for Bloom filter implementation.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

try:
    from bloom_filter import BloomFilter
    print("✓ BloomFilter import successful")
except ImportError as e:
    print(f"✗ BloomFilter import failed: {e}")
    sys.exit(1)

def test_bloom_filter():
    print("\nTesting Bloom filter functionality...")

    # Create a small Bloom filter for testing
    bf = BloomFilter(expected_items=1000, false_positive_rate=0.01)

    # Test basic operations
    test_passwords = ["password123", "admin123", "letmein", "qwerty"]

    # Add passwords
    for pwd in test_passwords:
        bf.add(pwd)

    print("✓ Added test passwords to Bloom filter")

    # Test known passwords (should return True)
    for pwd in test_passwords:
        result = bf.check(pwd)
        if result:
            print(f"✓ Correctly identified '{pwd}' as probably in set")
        else:
            print(f"✗ Failed to identify '{pwd}' as in set")

    # Test unknown passwords (should mostly return False)
    unknown_passwords = ["mysecretpassword", "supersecure123", "uniquepass"]
    false_positives = 0

    for pwd in unknown_passwords:
        result = bf.check(pwd)
        if result:
            print(f"⚠ False positive for '{pwd}'")
            false_positives += 1
        else:
            print(f"✓ Correctly identified '{pwd}' as not in set")

    # Save and load test
    try:
        test_file = "test_bloom_filter.dat"
        bf.save(test_file)
        bf_loaded = BloomFilter.load(test_file)

        # Test that loaded filter works the same
        for pwd in test_passwords:
            if bf_loaded.check(pwd):
                print(f"✓ Loaded filter correctly identifies '{pwd}'")
            else:
                print(f"✗ Loaded filter failed to identify '{pwd}'")

        # Clean up
        import os
        if os.path.exists(test_file):
            os.remove(test_file)

        print("✓ Save/load functionality working correctly")

    except Exception as e:
        print(f"✗ Save/load test failed: {e}")

    print(f"\nTest completed with {false_positives} false positives out of {len(unknown_passwords)}")

def test_password_strength_integration():
    print("\nTesting PasswordStrengthChecker integration...")

    try:
        import os
        import shutil
        from password_strength import PasswordStrengthChecker

        # Create a checker with a small test directory
        test_dir = "data/test_wordlists"
        os.makedirs(test_dir, exist_ok=True)

        # Create a small test wordlist
        test_wordlist = os.path.join(test_dir, "test.txt")
        with open(test_wordlist, "w") as f:
            f.write("password123\n")
            f.write("admin123\n")
            f.write("letmein\n")

        # Create checker
        checker = PasswordStrengthChecker(test_dir)

        # Test known leaked password
        if checker.is_password_leaked("password123"):
            print("✓ PasswordStrengthChecker correctly identified leaked password")
        else:
            print("✗ PasswordStrengthChecker failed to identify leaked password")

        # Test non-leaked password
        if not checker.is_password_leaked("mysecretpassword123"):
            print("✓ PasswordStrengthChecker correctly identified non-leaked password")
        else:
            print("✗ PasswordStrengthChecker incorrectly flagged non-leaked password")

        # Clean up
        if os.path.exists(test_wordlist):
            os.remove(test_wordlist)
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)

        print("✓ PasswordStrengthChecker integration test completed")

    except Exception as e:
        print(f"✗ PasswordStrengthChecker integration test failed: {e}")

if __name__ == "__main__":
    print("Running Bloom filter tests...")

    test_bloom_filter()
    test_password_strength_integration()

    print("\nAll tests completed!")
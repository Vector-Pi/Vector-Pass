import hashlib
import math
import pickle
import os
from typing import List, Union


class BloomFilter:
    def __init__(self, expected_items: int = 50000000, false_positive_rate: float = 0.01):
        """
        Initialize a Bloom filter optimized for password leak detection.

        Args:
            expected_items: Expected number of items to store (default: 50M passwords)
            false_positive_rate: Acceptable false positive rate (default: 1%)
        """
        self.expected_items = expected_items
        self.false_positive_rate = false_positive_rate

        # Calculate optimal parameters
        self.bit_array_size = self._calculate_bit_array_size()
        self.hash_count = self._calculate_hash_count()

        # Initialize bit array
        self.bit_array = bytearray((self.bit_array_size + 7) // 8)  # Ceiling division for bytes

    def _calculate_bit_array_size(self) -> int:
        """
        Calculate optimal bit array size based on expected items and false positive rate.

        Formula: m = -(n * ln(p)) / (ln(2)^2)
        Where:
        - n = expected_items
        - p = false_positive_rate
        """
        if self.false_positive_rate <= 0 or self.false_positive_rate >= 1:
            raise ValueError("False positive rate must be between 0 and 1")

        size = -(self.expected_items * math.log(self.false_positive_rate)) / (math.log(2) ** 2)
        return max(int(size), 1000)  # Minimum size to avoid issues

    def _calculate_hash_count(self) -> int:
        """
        Calculate optimal number of hash functions.

        Formula: k = (m/n) * ln(2)
        Where:
        - m = bit_array_size
        - n = expected_items
        """
        if self.bit_array_size == 0 or self.expected_items == 0:
            return 1

        count = (self.bit_array_size / self.expected_items) * math.log(2)
        return max(int(count), 1)

    def _hash_functions(self, item: str) -> List[int]:
        """
        Generate k hash values for an item using double hashing technique.

        Args:
            item: String to hash

        Returns:
            List of k hash values
        """
        # Convert item to bytes
        item_bytes = item.encode('utf-8')

        # Two different hash functions as seeds
        hash1 = int(hashlib.md5(item_bytes).hexdigest(), 16)
        hash2 = int(hashlib.sha256(item_bytes).hexdigest(), 16)

        # Generate k hash values using double hashing
        hash_values = []
        for i in range(self.hash_count):
            # Double hashing formula: (hash1 + i * hash2) mod bit_array_size
            combined_hash = (hash1 + i * hash2) % self.bit_array_size
            hash_values.append(combined_hash)

        return hash_values

    def add(self, item: str) -> None:
        """
        Add an item to the Bloom filter.

        Args:
            item: String to add to the filter
        """
        if not isinstance(item, str):
            raise TypeError("Item must be a string")

        # Normalize item (lowercase) for consistent hashing
        normalized_item = item.lower()
        hash_values = self._hash_functions(normalized_item)

        # Set corresponding bits to 1
        for hash_val in hash_values:
            byte_index = hash_val // 8
            bit_index = hash_val % 8
            self.bit_array[byte_index] |= (1 << bit_index)

    def check(self, item: str) -> bool:
        """
        Check if an item is probably in the set.

        Args:
            item: String to check

        Returns:
            True if item is probably in the set, False if definitely not
        """
        if not isinstance(item, str):
            raise TypeError("Item must be a string")

        # Normalize item (lowercase) for consistent hashing
        normalized_item = item.lower()
        hash_values = self._hash_functions(normalized_item)

        # Check if all corresponding bits are set
        for hash_val in hash_values:
            byte_index = hash_val // 8
            bit_index = hash_val % 8
            if not (self.bit_array[byte_index] & (1 << bit_index)):
                return False  # Definitely not in set

        return True  # Probably in set

    def save(self, filepath: str) -> None:
        """
        Serialize and save the Bloom filter to a file.

        Args:
            filepath: Path to save the serialized filter
        """
        data = {
            'expected_items': self.expected_items,
            'false_positive_rate': self.false_positive_rate,
            'bit_array_size': self.bit_array_size,
            'hash_count': self.hash_count,
            'bit_array': self.bit_array
        }

        with open(filepath, 'wb') as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, filepath: str) -> 'BloomFilter':
        """
        Load a serialized Bloom filter from a file.

        Args:
            filepath: Path to the serialized filter

        Returns:
            Loaded BloomFilter instance
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Bloom filter file not found: {filepath}")

        with open(filepath, 'rb') as f:
            data = pickle.load(f)

        # Create new instance with saved parameters
        bf = cls(data['expected_items'], data['false_positive_rate'])

        # Restore saved data
        bf.bit_array_size = data['bit_array_size']
        bf.hash_count = data['hash_count']
        bf.bit_array = data['bit_array']

        return bf

    def get_stats(self) -> dict:
        """
        Get statistics about the Bloom filter.

        Returns:
            Dictionary with filter statistics
        """
        # Count set bits (approximate)
        set_bits = sum(bin(byte).count('1') for byte in self.bit_array)
        fill_ratio = set_bits / (self.bit_array_size or 1)

        return {
            'expected_items': self.expected_items,
            'false_positive_rate': self.false_positive_rate,
            'bit_array_size': self.bit_array_size,
            'hash_count': self.hash_count,
            'estimated_fill_ratio': fill_ratio,
            'memory_usage_bytes': len(self.bit_array)
        }


def build_bloom_filter_from_wordlists(
    wordlist_dir: str,
    output_file: str,
    expected_items: int = 50000000,
    false_positive_rate: float = 0.01
) -> BloomFilter:
    """
    Build a Bloom filter from wordlist files.

    Args:
        wordlist_dir: Directory containing wordlist .txt files
        output_file: Path to save the serialized Bloom filter
        expected_items: Expected number of items (optimization hint)
        false_positive_rate: Acceptable false positive rate

    Returns:
        Built BloomFilter instance
    """
    import os

    print(f"Building Bloom filter from wordlists in {wordlist_dir}")

    # Create Bloom filter
    bf = BloomFilter(expected_items, false_positive_rate)

    # Counter for progress tracking
    total_passwords = 0

    # Process all .txt files in directory
    try:
        for filename in os.listdir(wordlist_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(wordlist_dir, filename)
                print(f"Processing {filename}...")

                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        password = line.strip()
                        if password:  # Skip empty lines
                            bf.add(password)
                            total_passwords += 1

                print(f"  Processed {total_passwords} passwords so far")

    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist directory not found: {wordlist_dir}")
    except Exception as e:
        raise Exception(f"Error processing wordlists: {e}")

    # Save the filter
    bf.save(output_file)
    print(f"Saved Bloom filter with {total_passwords} passwords to {output_file}")

    # Print statistics
    stats = bf.get_stats()
    print(f"Filter statistics:")
    print(f"  Memory usage: {stats['memory_usage_bytes'] / (1024*1024):.1f} MB")
    print(f"  Bit array size: {stats['bit_array_size']:,} bits")
    print(f"  Hash functions: {stats['hash_count']}")
    print(f"  Fill ratio: {stats['estimated_fill_ratio']:.3f}")

    return bf


# Example usage:
if __name__ == "__main__":
    # Example of building and using a Bloom filter
    bf = BloomFilter(expected_items=1000000, false_positive_rate=0.01)

    # Add some test passwords
    test_passwords = ["password123", "admin123", "letmein", "qwerty"]
    for pwd in test_passwords:
        bf.add(pwd)

    # Check passwords
    print("Checking passwords:")
    for pwd in ["password123", "mypassword", "admin123", "unknown"]:
        result = bf.check(pwd)
        print(f"  {pwd}: {'Probably leaked' if result else 'Not leaked'}")

    # Save and load example
    bf.save("test_bloom_filter.dat")
    bf_loaded = BloomFilter.load("test_bloom_filter.dat")
    print(f"Loaded filter check: {bf_loaded.check('password123')}")

    # Clean up test file
    if os.path.exists("test_bloom_filter.dat"):
        os.remove("test_bloom_filter.dat")
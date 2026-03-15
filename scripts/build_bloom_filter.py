#!/usr/bin/env python3
"""
Script to build a Bloom filter from password wordlists.

This script processes all .txt files in the data/leaked_passwords directory
and creates a serialized Bloom filter for fast password leak detection.
"""

import os
import sys
import argparse
import time
from pathlib import Path

# Add src to path so we can import bloom_filter
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

try:
    from bloom_filter import build_bloom_filter_from_wordlists
except ImportError:
    print("Error: Could not import bloom_filter module")
    print("Make sure you're running this script from the project root")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Build Bloom filter from password wordlists')
    parser.add_argument('--wordlist-dir', default='data/leaked_passwords',
                       help='Directory containing wordlist files (default: data/leaked_passwords)')
    parser.add_argument('--output-file', default='data/leaked_passwords/bloom_filter.dat',
                       help='Output file for serialized Bloom filter (default: data/leaked_passwords/bloom_filter.dat)')
    parser.add_argument('--expected-items', type=int, default=50000000,
                       help='Expected number of items (default: 50000000)')
    parser.add_argument('--false-positive-rate', type=float, default=0.01,
                       help='False positive rate (default: 0.01)')

    args = parser.parse_args()

    # Validate input directory
    if not os.path.exists(args.wordlist_dir):
        print(f"Error: Wordlist directory not found: {args.wordlist_dir}")
        sys.exit(1)

    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(args.output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"Building Bloom filter from wordlists in: {args.wordlist_dir}")
    print(f"Output file: {args.output_file}")
    print(f"Expected items: {args.expected_items:,}")
    print(f"False positive rate: {args.false_positive_rate}")
    print("-" * 50)

    start_time = time.time()

    try:
        # Build the Bloom filter
        bf = build_bloom_filter_from_wordlists(
            wordlist_dir=args.wordlist_dir,
            output_file=args.output_file,
            expected_items=args.expected_items,
            false_positive_rate=args.false_positive_rate
        )

        elapsed_time = time.time() - start_time

        print("-" * 50)
        print(f"Successfully built Bloom filter in {elapsed_time:.2f} seconds")
        print(f"Memory usage: {bf.get_stats()['memory_usage_bytes'] / (1024*1024):.1f} MB")

    except Exception as e:
        print(f"Error building Bloom filter: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
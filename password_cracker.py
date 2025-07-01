import hashlib
import argparse
import sys
from typing import Optional

def hash_password(password: str, algorithm: str = 'md5') -> str:
    """Hash a password using the specified algorithm.
    
    Args:
        password: The password to hash
        algorithm: The hashing algorithm to use (default: md5)
        
    Returns:
        The hashed password as a hexadecimal string
    """
    if algorithm.lower() == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm.lower() == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm.lower() == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError(f'Unsupported hashing algorithm: {algorithm}')

def crack_password(hash_value: str, wordlist_file: str, algorithm: str = 'md5') -> Optional[str]:
    """Attempt to crack a password hash using a dictionary attack.
    
    Args:
        hash_value: The hash to crack
        wordlist_file: Path to the wordlist file
        algorithm: The hashing algorithm used (default: md5)
        
    Returns:
        The cracked password if found, None otherwise
    """
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if hash_password(password, algorithm) == hash_value.lower():
                    return password
        return None
    except FileNotFoundError:
        print(f'Error: Wordlist file {wordlist_file} not found')
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Password Hash Cracker')
    parser.add_argument('hash', help='The hash to crack')
    parser.add_argument('wordlist', help='Path to the wordlist file')
    parser.add_argument('--algorithm', '-a', default='md5',
                        choices=['md5', 'sha1', 'sha256'],
                        help='Hashing algorithm (default: md5)')
    
    args = parser.parse_args()
    
    print(f'Attempting to crack {args.algorithm.upper()} hash: {args.hash}')
    print(f'Using wordlist: {args.wordlist}')
    
    result = crack_password(args.hash, args.wordlist, args.algorithm)
    
    if result:
        print(f'\nPassword found: {result}')
    else:
        print('\nPassword not found in wordlist')

if __name__ == '__main__':
    main()
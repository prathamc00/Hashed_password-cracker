import hashlib
import argparse
import sys
from typing import Optional, List, Tuple
from hash_identifier import HashIdentifier

def hash_password(password: str, algorithm: str = 'md5') -> str:
    """Hash a password using the specified algorithm.
    
    Args:
        password: The password to hash
        algorithm: The hashing algorithm to use (default: md5)
        
    Returns:
        The hashed password as a hexadecimal string
    """
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    algorithm = algorithm.lower()
    if algorithm in algorithms:
        return algorithms[algorithm](password.encode()).hexdigest()
    else:
        raise ValueError(f'Unsupported hashing algorithm: {algorithm}')

def identify_hash_type(hash_value: str) -> List[Tuple[str, dict]]:
    """Identify possible hash types and their information.
    
    Args:
        hash_value: The hash to identify
        
    Returns:
        List of tuples containing hash type and its information
    """
    possible_types = HashIdentifier.identify_hash(hash_value)
    return [(hash_type, HashIdentifier.get_hash_info(hash_type)) 
            for hash_type in possible_types]

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
        # Identify possible hash types if algorithm is not specified
        if algorithm == 'auto':
            possible_types = identify_hash_type(hash_value)
            if not possible_types:
                print('Could not identify hash type. Please specify algorithm manually.')
                return None
            
            # Try each possible algorithm
            for hash_type, info in possible_types:
                print(f'Trying {hash_type} ({info["description"]})')
                algorithm = hash_type.lower()
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        password = line.strip()
                        if hash_password(password, algorithm) == hash_value.lower():
                            return password
            return None
        
        # Traditional single algorithm approach
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
    parser.add_argument('--algorithm', '-a', default='auto',
                        choices=['auto', 'md5', 'sha1', 'sha256', 'sha512'],
                        help='Hashing algorithm (default: auto-detect)')
    parser.add_argument('--identify', '-i', action='store_true',
                        help='Only identify the hash type without cracking')
    
    args = parser.parse_args()
    
    # Identify hash type
    if args.identify:
        possible_types = identify_hash_type(args.hash)
        if possible_types:
            print('\nPossible hash types:')
            for hash_type, info in possible_types:
                print(f'\n{hash_type}:')
                print(f'  Length: {info["length"]} characters')
                print(f'  Complexity: {info["complexity"]}')
                print(f'  Description: {info["description"]}')
                print(f'  Year introduced: {info["year"]}')
        else:
            print('\nUnknown hash type')
        return
    
    # Crack the hash
    if args.algorithm == 'auto':
        print(f'Attempting to crack hash: {args.hash}')
        print('Using automatic hash type detection')
    else:
        print(f'Attempting to crack {args.algorithm.upper()} hash: {args.hash}')
    print(f'Using wordlist: {args.wordlist}')
    
    result = crack_password(args.hash, args.wordlist, args.algorithm)
    
    if result:
        print(f'\nPassword found: {result}')
    else:
        print('\nPassword not found in wordlist')

if __name__ == '__main__':
    main()
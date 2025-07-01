import hashlib
import json
from typing import Dict, List
from hash_utils import HashUtils

class RainbowTable:
    def __init__(self, table_file: str = 'rainbow_table.json'):
        """Initialize the rainbow table.
        
        Args:
            table_file: Path to the JSON file storing the rainbow table
        """
        self.table_file = table_file
        self.table: Dict[str, Dict[str, str]] = {}
        self.load_table()
    
    def load_table(self) -> None:
        """Load the rainbow table from file if it exists."""
        try:
            with open(self.table_file, 'r') as f:
                self.table = json.load(f)
        except FileNotFoundError:
            self.table = {}
    
    def save_table(self) -> None:
        """Save the rainbow table to file."""
        with open(self.table_file, 'w') as f:
            json.dump(self.table, f, indent=2)
    
    def generate_table(self, wordlist_file: str) -> None:
        """Generate a rainbow table from a wordlist.
        
        Args:
            wordlist_file: Path to the wordlist file
        """
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password:
                        # Generate all hash variants
                        hash_variants = HashUtils.generate_hash_variants(password)
                        self.table[password] = hash_variants
            
            # Save the generated table
            self.save_table()
            
        except FileNotFoundError:
            raise FileNotFoundError(f'Wordlist file {wordlist_file} not found')
    
    def lookup_hash(self, hash_value: str) -> List[Dict[str, str]]:
        """Look up a hash in the rainbow table.
        
        Args:
            hash_value: The hash to look up
            
        Returns:
            List of dictionaries containing matched passwords and algorithms
        """
        matches = []
        hash_value = hash_value.lower()
        
        for password, variants in self.table.items():
            for algorithm, hash_variant in variants.items():
                if hash_variant.lower() == hash_value:
                    matches.append({
                        'password': password,
                        'algorithm': algorithm
                    })
        
        return matches
    
    def add_password(self, password: str) -> None:
        """Add a single password and its hash variants to the table.
        
        Args:
            password: The password to add
        """
        if password:
            hash_variants = HashUtils.generate_hash_variants(password)
            self.table[password] = hash_variants
            self.save_table()
    
    def remove_password(self, password: str) -> bool:
        """Remove a password and its hashes from the table.
        
        Args:
            password: The password to remove
            
        Returns:
            True if password was found and removed, False otherwise
        """
        if password in self.table:
            del self.table[password]
            self.save_table()
            return True
        return False
    
    def get_table_stats(self) -> Dict[str, int]:
        """Get statistics about the rainbow table.
        
        Returns:
            Dictionary containing table statistics
        """
        return {
            'total_passwords': len(self.table),
            'total_hashes': sum(len(variants) for variants in self.table.values())
        }

def main():
    # Example usage
    rainbow = RainbowTable()
    
    # Generate table from wordlist
    try:
        rainbow.generate_table('sample_wordlist.txt')
        print('Rainbow table generated successfully')
        
        # Print statistics
        stats = rainbow.get_table_stats()
        print(f'Total passwords: {stats["total_passwords"]}')
        print(f'Total hashes: {stats["total_hashes"]}')
        
    except FileNotFoundError as e:
        print(f'Error: {e}')

if __name__ == '__main__':
    main()
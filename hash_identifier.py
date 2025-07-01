import re

class HashIdentifier:
    HASH_PATTERNS = {
        'MD5': (r'^[a-fA-F0-9]{32}$', 32),
        'SHA1': (r'^[a-fA-F0-9]{40}$', 40),
        'SHA256': (r'^[a-fA-F0-9]{64}$', 64),
        'SHA512': (r'^[a-fA-F0-9]{128}$', 128),
        'NTLM': (r'^[a-fA-F0-9]{32}$', 32),
        'MySQL': (r'^\*[A-F0-9]{40}$', 41),
        'BCrypt': (r'^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9\/.]{53}$', 60)
    }

    @staticmethod
    def identify_hash(hash_string):
        """Identify the type of hash based on its pattern and length.
        
        Args:
            hash_string: The hash to identify
            
        Returns:
            A list of possible hash types
        """
        possible_types = []
        
        # Clean the hash string
        hash_string = hash_string.strip()
        
        # Check against each pattern
        for hash_type, (pattern, length) in HashIdentifier.HASH_PATTERNS.items():
            if len(hash_string) == length and re.match(pattern, hash_string):
                possible_types.append(hash_type)
        
        return possible_types

    @staticmethod
    def get_hash_info(hash_type):
        """Get information about a specific hash type.
        
        Args:
            hash_type: The type of hash (e.g., 'MD5', 'SHA1')
            
        Returns:
            A dictionary containing information about the hash type
        """
        hash_info = {
            'MD5': {
                'length': 32,
                'complexity': 'Low',
                'description': '128-bit hash, not recommended for security',
                'year': 1992
            },
            'SHA1': {
                'length': 40,
                'complexity': 'Low',
                'description': '160-bit hash, deprecated for security use',
                'year': 1995
            },
            'SHA256': {
                'length': 64,
                'complexity': 'High',
                'description': '256-bit hash, recommended for security',
                'year': 2001
            },
            'SHA512': {
                'length': 128,
                'complexity': 'Very High',
                'description': '512-bit hash, recommended for security',
                'year': 2001
            },
            'NTLM': {
                'length': 32,
                'complexity': 'Low',
                'description': 'Windows password hash, vulnerable to attacks',
                'year': 1993
            },
            'MySQL': {
                'length': 41,
                'complexity': 'Medium',
                'description': 'MySQL password hash with salt',
                'year': 2000
            },
            'BCrypt': {
                'length': 60,
                'complexity': 'Very High',
                'description': 'Adaptive hash function with salt and cost factor',
                'year': 1999
            }
        }
        
        return hash_info.get(hash_type, {
            'length': 'Unknown',
            'complexity': 'Unknown',
            'description': 'Unknown hash type',
            'year': 'Unknown'
        })
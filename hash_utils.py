import hashlib
import re
import base64
from typing import Optional, List, Dict, Tuple

class HashUtils:
    @staticmethod
    def generate_hash_variants(text: str) -> Dict[str, str]:
        """Generate different hash variants of a given text.
        
        Args:
            text: The text to hash
            
        Returns:
            Dictionary of algorithm names and their corresponding hashes
        """
        variants = {}
        text_bytes = text.encode()
        
        # Standard hashes
        variants['md5'] = hashlib.md5(text_bytes).hexdigest()
        variants['sha1'] = hashlib.sha1(text_bytes).hexdigest()
        variants['sha256'] = hashlib.sha256(text_bytes).hexdigest()
        variants['sha512'] = hashlib.sha512(text_bytes).hexdigest()
        
        # Base64 encoded variants
        variants['base64'] = base64.b64encode(text_bytes).decode()
        variants['base64_md5'] = base64.b64encode(hashlib.md5(text_bytes).digest()).decode()
        variants['base64_sha1'] = base64.b64encode(hashlib.sha1(text_bytes).digest()).decode()
        
        return variants
    
    @staticmethod
    def analyze_hash_strength(hash_value: str) -> Dict[str, any]:
        """Analyze the strength characteristics of a hash.
        
        Args:
            hash_value: The hash to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        analysis = {
            'length': len(hash_value),
            'character_types': {
                'lowercase': len(re.findall(r'[a-z]', hash_value)),
                'uppercase': len(re.findall(r'[A-Z]', hash_value)),
                'digits': len(re.findall(r'\d', hash_value)),
                'special': len(re.findall(r'[^a-zA-Z0-9]', hash_value))
            },
            'entropy': HashUtils._calculate_entropy(hash_value),
            'is_hex': bool(re.match(r'^[a-fA-F0-9]+$', hash_value))
        }
        
        # Add strength rating
        analysis['strength_rating'] = HashUtils._rate_hash_strength(analysis)
        
        return analysis
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate the Shannon entropy of a text string.
        
        Args:
            text: The text to analyze
            
        Returns:
            Entropy value as a float
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * (probability.bit_length())
        
        return entropy
    
    @staticmethod
    def _rate_hash_strength(analysis: Dict[str, any]) -> str:
        """Rate the strength of a hash based on its characteristics.
        
        Args:
            analysis: Hash analysis dictionary
            
        Returns:
            Strength rating as a string
        """
        score = 0
        
        # Length contribution
        length_scores = {32: 1, 40: 2, 64: 3, 128: 4}
        score += length_scores.get(analysis['length'], 0)
        
        # Character type variety contribution
        char_types = sum(1 for count in analysis['character_types'].values() if count > 0)
        score += char_types
        
        # Entropy contribution
        if analysis['entropy'] > 3.0:
            score += 2
        elif analysis['entropy'] > 2.0:
            score += 1
        
        # Final rating
        if score >= 7:
            return 'Very Strong'
        elif score >= 5:
            return 'Strong'
        elif score >= 3:
            return 'Moderate'
        else:
            return 'Weak'
    
    @staticmethod
    def detect_common_patterns(hash_value: str) -> List[str]:
        """Detect common patterns in the hash that might indicate its type.
        
        Args:
            hash_value: The hash to analyze
            
        Returns:
            List of detected patterns
        """
        patterns = []
        
        # Check for common patterns
        if re.match(r'^\$2[ayb]\$', hash_value):
            patterns.append('BCrypt format')
        elif re.match(r'^\{SHA\}', hash_value):
            patterns.append('LDAP SHA hash')
        elif re.match(r'^[0-9a-f]{32}$', hash_value, re.I):
            patterns.append('Possible MD5 or NTLM')
        elif re.match(r'^[0-9a-f]{40}$', hash_value, re.I):
            patterns.append('Possible SHA1')
        elif re.match(r'^[0-9a-f]{64}$', hash_value, re.I):
            patterns.append('Possible SHA256')
        elif re.match(r'^[0-9a-f]{128}$', hash_value, re.I):
            patterns.append('Possible SHA512')
        elif re.match(r'^[a-zA-Z0-9+/]+={0,2}$', hash_value):
            patterns.append('Possible Base64 encoding')
        
        return patterns
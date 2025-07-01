import re
import math
from typing import Dict, List, Tuple
from collections import Counter
from hash_utils import HashUtils

class HashAnalyzer:
    def __init__(self):
        self.common_lengths = {
            32: ['MD5', 'NTLM'],
            40: ['SHA1'],
            64: ['SHA256', 'RIPEMD-160'],
            96: ['SHA384'],
            128: ['SHA512'],
            60: ['BCrypt']
        }
    
    def analyze_hash(self, hash_value: str) -> Dict[str, any]:
        """Perform comprehensive analysis of a hash value.
        
        Args:
            hash_value: The hash to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        analysis = {
            'basic_stats': self._get_basic_stats(hash_value),
            'character_distribution': self._analyze_char_distribution(hash_value),
            'possible_algorithms': self._identify_possible_algorithms(hash_value),
            'patterns': self._detect_patterns(hash_value),
            'strength_analysis': HashUtils.analyze_hash_strength(hash_value)
        }
        
        # Add overall assessment
        analysis['assessment'] = self._generate_assessment(analysis)
        
        return analysis
    
    def _get_basic_stats(self, hash_value: str) -> Dict[str, any]:
        """Get basic statistical information about the hash.
        
        Args:
            hash_value: The hash to analyze
            
        Returns:
            Dictionary containing basic statistics
        """
        return {
            'length': len(hash_value),
            'unique_chars': len(set(hash_value)),
            'is_hex': bool(re.match(r'^[a-fA-F0-9]+$', hash_value)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', hash_value))
        }
    
    def _analyze_char_distribution(self, hash_value: str) -> Dict[str, float]:
        """Analyze the distribution of characters in the hash.
        
        Args:
            hash_value: The hash to analyze
            
        Returns:
            Dictionary containing distribution metrics
        """
        # Count character frequencies
        char_count = Counter(hash_value)
        total_chars = len(hash_value)
        
        # Calculate distribution metrics
        distribution = {
            'entropy': self._calculate_entropy(char_count, total_chars),
            'chi_square': self._calculate_chi_square(char_count, total_chars),
            'character_frequencies': {char: count/total_chars 
                                    for char, count in char_count.items()}
        }
        
        return distribution
    
    def _calculate_entropy(self, char_count: Counter, total_chars: int) -> float:
        """Calculate Shannon entropy of the hash.
        
        Args:
            char_count: Counter object with character frequencies
            total_chars: Total number of characters
            
        Returns:
            Entropy value
        """
        entropy = 0
        for count in char_count.values():
            prob = count / total_chars
            entropy -= prob * math.log2(prob)
        return entropy
    
    def _calculate_chi_square(self, char_count: Counter, total_chars: int) -> float:
        """Calculate chi-square statistic for character distribution.
        
        Args:
            char_count: Counter object with character frequencies
            total_chars: Total number of characters
            
        Returns:
            Chi-square value
        """
        expected = total_chars / len(char_count)
        chi_square = sum((count - expected) ** 2 / expected 
                        for count in char_count.values())
        return chi_square
    
    def _identify_possible_algorithms(self, hash_value: str) -> List[str]:
        """Identify possible hashing algorithms based on characteristics.
        
        Args:
            hash_value: The hash to analyze
            
        Returns:
            List of possible algorithms
        """
        possible = []
        length = len(hash_value)
        
        # Check common lengths
        if length in self.common_lengths:
            possible.extend(self.common_lengths[length])
        
        # Check specific patterns
        if re.match(r'^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9\/.]{53}$', hash_value):
            possible.append('BCrypt')
        elif re.match(r'^[0-9a-f]{32}$', hash_value, re.I):
            if not any(c.isupper() for c in hash_value):
                possible.append('MD5 (lowercase)')
            else:
                possible.append('MD5 (mixed case)')
        
        return possible
    
    def _detect_patterns(self, hash_value: str) -> List[str]:
        """Detect specific patterns in the hash.
        
        Args:
            hash_value: The hash to analyze
            
        Returns:
            List of detected patterns
        """
        patterns = []
        
        # Check for salted hash patterns
        if '$' in hash_value:
            patterns.append('Contains separator (possible salt)')
        
        # Check for common encodings
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', hash_value):
            patterns.append('Possible Base64 encoding')
        
        # Check for repeated patterns
        if self._has_repeated_sequences(hash_value):
            patterns.append('Contains repeated sequences')
        
        return patterns
    
    def _has_repeated_sequences(self, hash_value: str, min_length: int = 3) -> bool:
        """Check for repeated sequences in the hash.
        
        Args:
            hash_value: The hash to analyze
            min_length: Minimum length of sequences to check
            
        Returns:
            True if repeated sequences found, False otherwise
        """
        for i in range(len(hash_value) - min_length + 1):
            sequence = hash_value[i:i+min_length]
            if hash_value.count(sequence) > 1:
                return True
        return False
    
    def _generate_assessment(self, analysis: Dict[str, any]) -> str:
        """Generate an overall assessment of the hash.
        
        Args:
            analysis: Complete analysis dictionary
            
        Returns:
            Assessment string
        """
        assessment_points = []
        
        # Check basic characteristics
        if analysis['basic_stats']['is_hex']:
            assessment_points.append('Standard hexadecimal format')
        if analysis['basic_stats']['has_special']:
            assessment_points.append('Contains special characters')
        
        # Check entropy
        entropy = analysis['character_distribution']['entropy']
        if entropy > 3.0:
            assessment_points.append('High entropy (good randomness)')
        elif entropy < 2.0:
            assessment_points.append('Low entropy (possible pattern)')
        
        # Add algorithm suggestions
        if analysis['possible_algorithms']:
            algorithms = ', '.join(analysis['possible_algorithms'])
            assessment_points.append(f'Likely algorithms: {algorithms}')
        
        # Add strength assessment
        assessment_points.append(
            f'Overall strength: {analysis["strength_analysis"]["strength_rating"]}')
        
        return ' | '.join(assessment_points)

def main():
    # Example usage
    analyzer = HashAnalyzer()
    
    # Example hashes to analyze
    test_hashes = [
        '5f4dcc3b5aa765d61d8327deb882cf99',  # MD5
        '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',  # BCrypt
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'  # SHA256
    ]
    
    for hash_value in test_hashes:
        print(f'\nAnalyzing hash: {hash_value}')
        analysis = analyzer.analyze_hash(hash_value)
        print('\nAssessment:')
        print(analysis['assessment'])
        print('\nPossible algorithms:')
        print(', '.join(analysis['possible_algorithms']))

if __name__ == '__main__':
    main()
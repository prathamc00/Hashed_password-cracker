# Hashed Password Cracker

A Python-based tool for identifying and cracking password hashes using dictionary attacks. Features both a command-line interface and a modern web interface!

## Features

### Hash Support
- Supports multiple hashing algorithms:
  - MD5 (128-bit)
  - SHA1 (160-bit)
  - SHA256 (256-bit)
  - SHA512 (512-bit)
  - NTLM (Windows passwords)
  - MySQL (41-character)
  - BCrypt (60-character)

### Hash Identification
- Automatic hash type detection
- Detailed hash information:
  - Algorithm complexity
  - Historical context
  - Security recommendations
  - Technical specifications

### Cracking Capabilities
- Dictionary attack using custom wordlists
- Auto-detection of hash type for cracking
- Multiple algorithm attempts for ambiguous hashes

### User Interface
- Command-line interface for scripting and automation
- Modern web interface with:
  - Real-time hash generation
  - Hash type identification
  - Password cracking
  - Responsive design using Tailwind CSS

## Requirements

- Python 3.6 or higher
- Flask (for web interface)
- Internet connection (for Tailwind CSS CDN and jQuery)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/hashed-password-cracker.git
   cd hashed-password-cracker
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

```bash
# Identify a hash type
python password_cracker.py <hash> <wordlist> --identify

# Crack a hash with automatic type detection
python password_cracker.py <hash> <wordlist>

# Crack a hash using a specific algorithm
python password_cracker.py <hash> <wordlist> --algorithm sha256
```

### Web Interface

1. Start the Flask server:
   ```bash
   python app.py
   ```

2. Open your browser and navigate to `http://localhost:5000`

3. Use the web interface to:
   - Generate hashes from passwords
   - Identify unknown hash types
   - Get detailed hash information
   - Crack password hashes
   - Choose different hashing algorithms
   - Use automatic hash type detection

## Security Notice

This tool is for educational and testing purposes only. Please note:

- Do not use it to crack passwords without proper authorization
- Unauthorized password cracking may be illegal and unethical
- Some included hash algorithms (MD5, SHA1) are considered cryptographically broken
- For secure password storage, use modern algorithms like BCrypt with proper salting
- This tool can help identify weak password hashing implementations

## Hash Types Information

### Supported Hash Types and Their Security Status

1. **MD5**
   - Length: 32 characters
   - Status: Cryptographically broken
   - Use Case: Legacy systems, file checksums

2. **SHA1**
   - Length: 40 characters
   - Status: Cryptographically broken
   - Use Case: Legacy systems, Git version control

3. **SHA256**
   - Length: 64 characters
   - Status: Cryptographically secure
   - Use Case: Modern security applications

4. **SHA512**
   - Length: 128 characters
   - Status: Cryptographically secure
   - Use Case: High-security applications

5. **NTLM**
   - Length: 32 characters
   - Status: Vulnerable to attacks
   - Use Case: Windows password hashes

6. **MySQL**
   - Length: 41 characters
   - Status: Moderately secure (with proper salting)
   - Use Case: MySQL database password storage

7. **BCrypt**
   - Length: 60 characters
   - Status: Highly secure
   - Use Case: Modern password storage

## Project Structure

```
.
├── app.py                 # Flask web application
├── password_cracker.py    # Core password cracking functionality
├── hash_identifier.py     # Hash type identification module
├── requirements.txt       # Python dependencies
├── README.md             # Project documentation
├── sample_wordlist.txt    # Sample wordlist for testing
└── templates/
    └── index.html        # Web interface template
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
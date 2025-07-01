# Hashed Password Cracker

A Python-based tool for cracking password hashes using dictionary attacks. This tool supports multiple hashing algorithms including MD5, SHA1, and SHA256. Available both as a command-line tool and a web application.

## Features

- Support for multiple hashing algorithms (MD5, SHA1, SHA256)
- Dictionary attack using custom wordlists
- Simple command-line interface
- Modern web interface with real-time hash generation and cracking
- UTF-8 encoding support for wordlists

## Requirements

- Python 3.6 or higher
- Flask (for web interface)
- Additional dependencies listed in requirements.txt

Install dependencies using:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

```bash
python password_cracker.py <hash> <wordlist> [--algorithm {md5,sha1,sha256}]
```

### Web Interface

Start the web server:
```bash
python app.py
```

Then open your browser and navigate to:
```
http://localhost:5000
```

The web interface provides two main functions:
1. **Hash Generator**: Create hashes from passwords using different algorithms
2. **Hash Cracker**: Attempt to crack password hashes using the built-in wordlist
```

### Arguments

- `hash`: The hash value you want to crack
- `wordlist`: Path to your dictionary file containing possible passwords (one per line)
- `--algorithm`, `-a`: The hashing algorithm used (default: md5)

### Example

```bash
# Crack an MD5 hash
python password_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt

# Crack a SHA256 hash
python password_cracker.py 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 wordlist.txt --algorithm sha256
```

## Included Files

1. **Sample Wordlist** (`sample_wordlist.txt`)
   - Contains common passwords for testing
   - One password per line
   - Useful for quick testing and demonstrations

2. **Common Hashes** (`common_hashes.txt`)
   - Reference file containing common passwords and their hashes
   - Format: `password:md5_hash:sha1_hash:sha256_hash`
   - Useful for learning and testing hash identification

## Creating Your Own Wordlist

You can enhance the cracking capability by:
- Creating your own custom wordlist
- Using publicly available wordlists (like rockyou.txt)
- Generate wordlists using tools like Crunch
- Combining multiple wordlists

## Security Notice

This tool is for educational purposes and legitimate security testing only. Do not use it to crack passwords without proper authorization.

## License

This project is open source and available under the MIT License.
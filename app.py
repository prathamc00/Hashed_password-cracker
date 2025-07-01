from flask import Flask, render_template, request, jsonify
from password_cracker import hash_password, crack_password
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/crack', methods=['POST'])
def crack():
    data = request.get_json()
    hash_value = data.get('hash')
    algorithm = data.get('algorithm', 'md5')
    
    if not hash_value:
        return jsonify({'error': 'Hash value is required'}), 400
    
    wordlist_path = os.path.join(os.path.dirname(__file__), 'sample_wordlist.txt')
    result = crack_password(hash_value, wordlist_path, algorithm)
    
    if result:
        return jsonify({'password': result})
    return jsonify({'message': 'Password not found in wordlist'})

@app.route('/hash', methods=['POST'])
def hash():
    data = request.get_json()
    password = data.get('password')
    algorithm = data.get('algorithm', 'md5')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    try:
        hashed = hash_password(password, algorithm)
        return jsonify({'hash': hashed})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
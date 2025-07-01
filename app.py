from flask import Flask, render_template, request, jsonify
from password_cracker import hash_password, crack_password, identify_hash_type

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/hash', methods=['POST'])
def hash():
    password = request.form.get('password')
    algorithm = request.form.get('algorithm', 'md5')
    
    if not password:
        return jsonify({'error': 'No password provided'})
    
    try:
        hashed = hash_password(password, algorithm)
        return jsonify({'hash': hashed})
    except ValueError as e:
        return jsonify({'error': str(e)})

@app.route('/identify', methods=['POST'])
def identify():
    hash_value = request.form.get('hash')
    
    if not hash_value:
        return jsonify({'error': 'No hash provided'})
    
    possible_types = identify_hash_type(hash_value)
    
    if possible_types:
        return jsonify({
            'types': [
                {
                    'name': hash_type,
                    'complexity': info['complexity'],
                    'description': info['description'],
                    'year': info['year']
                }
                for hash_type, info in possible_types
            ]
        })
    else:
        return jsonify({'error': 'Unknown hash type'})

@app.route('/crack', methods=['POST'])
def crack():
    hash_value = request.form.get('hash')
    algorithm = request.form.get('algorithm', 'auto')
    
    if not hash_value:
        return jsonify({'error': 'No hash provided'})
    
    result = crack_password(hash_value, 'sample_wordlist.txt', algorithm)
    
    if result:
        return jsonify({'password': result})
    else:
        return jsonify({'error': 'Password not found'})

if __name__ == '__main__':
    app.run(debug=True)
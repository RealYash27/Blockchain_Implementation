from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from uuid import uuid4
from time import time
from hashlib import sha256
from datetime import datetime
import pytz
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
import os
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key for session management

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.create_block(previous_hash='1', proof=100) 

    def create_block(self, proof, previous_hash):
        utc_time = datetime.utcfromtimestamp(time())  # Get the current UTC time
        ist = pytz.timezone('Asia/Kolkata')  # Timezone for IST
        ist_time = utc_time.replace(tzinfo=pytz.utc).astimezone(ist)

        block = {
            'index': len(self.chain) + 1,
            'timestamp': ist_time.strftime('%d-%m-%Y %H:%M:%S'),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash,
        }
        block['hash'] = sha256(str(block).encode()).hexdigest()
        self.current_transactions = []
        self.chain.append(block)
        return block

    def add_transaction(self, sender, receiver, amount):
        self.current_transactions.append({
            'sender': sender,
            'receiver': receiver,
            'amount': amount,
        })
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = sha256(guess).hexdigest()
        return guess_hash[:1] == "0"

# Initialize blockchain
blockchain = Blockchain()

# User data storage for demonstration (in-memory)
users = {}  # Key: username, Value: {'public_key': ..., 'private_key': ...}

# Helper function to generate wallet (public-private key pair)
def generate_wallet():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key.to_pem().decode(), public_key.to_pem().decode()

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    if username in users:
        return jsonify({'message': 'User already exists'}), 400
    private_key, public_key = generate_wallet()
    users[username] = {'public_key': public_key, 'private_key': private_key}
    return jsonify({'message': 'User registered successfully', 'public_key': public_key}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    if username not in users:
        return jsonify({'message': 'Invalid username'}), 401
    session['username'] = username
    return jsonify({'message': 'Logged in successfully'}), 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/create_transaction', methods=['POST'])
def create_transaction():
    if 'username' not in session:
        return jsonify({'message': 'User not authenticated'}), 401
    username = session['username']
    sender = users[username]['public_key']
    receiver = request.json.get('receiver')
    amount = request.json.get('amount')
    private_key_pem = users[username]['private_key']
    
    # Sign transaction
    private_key = SigningKey.from_pem(private_key_pem)
    transaction = {'sender': sender, 'receiver': receiver, 'amount': amount}
    transaction_data = f"{sender}{receiver}{amount}".encode()
    signature = private_key.sign(transaction_data).hex()

    blockchain.add_transaction(sender, receiver, amount)  # Add transaction to the blockchain
    return jsonify({'message': 'Transaction created', 'signature': signature}), 201

@app.route('/verify_transaction', methods=['POST'])
def verify_transaction():
    sender_public_key_pem = request.json.get('sender_public_key')
    transaction_data = request.json.get('transaction_data')
    signature = bytes.fromhex(request.json.get('signature'))
    
    public_key = VerifyingKey.from_pem(sender_public_key_pem)
    try:
        public_key.verify(signature, transaction_data.encode())
        return jsonify({'message': 'Transaction is valid'}), 200
    except BadSignatureError:
        return jsonify({'message': 'Invalid transaction signature'}), 400

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    blockchain.add_transaction(sender="0", receiver=session.get('username', 'Anonymous'), amount=1)
    
    previous_hash = blockchain.last_block['hash'] 
    block = blockchain.create_block(proof, previous_hash)

    response = {
        'message': "New Block Mined",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'hash': block['hash'],
    }
    return jsonify(response), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, jsonify, request, render_template
from uuid import uuid4
from time import time
from hashlib import sha256
from datetime import datetime
import pytz

app = Flask(__name__)

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
        
blockchain = Blockchain()


node_identifier = str(uuid4()).replace('-', '')



@app.route('/')
def index():
    return render_template('index.html')



@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'receiver', 'amount']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400

    index = blockchain.add_transaction(values['sender'], values['receiver'], values['amount'])
    return jsonify({'message': f'Transaction will be added to Block {index}'}), 201

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    blockchain.add_transaction(sender="0", receiver=node_identifier, amount=1)
    
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

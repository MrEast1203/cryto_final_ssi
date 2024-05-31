import hashlib
import pickle
import socket
import sys
import threading
import time
import random

import rsa


class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message


class Block:
    def __init__(self, previous_hash, difficulty, miner, miner_rewards):
        self.previous_hash = previous_hash
        self.hash = ''
        self.difficulty = difficulty
        self.nonce = 0
        self.timestamp = int(time.time())
        self.transactions = []
        self.miner = miner
        self.miner_rewards = miner_rewards
        self.did_documents = []

class DID_document:
    def __init__(self, id, verificationMethod, authentication):
        self.id = id
        self.verificationMethod = verificationMethod
        self.authentication = authentication

class BlockChain:
    def __init__(self):
        self.adjust_difficulty_blocks = 10
        self.difficulty = 1
        self.block_time = 30
        self.miner_rewards = 10
        self.block_limitation = 32
        self.chain = []
        self.pending_transactions = []
        self.pending_did_documents = []

        # For P2P connection
        self.socket_host = "127.0.0.1"
        self.socket_port = int(sys.argv[1])
        self.node_address = {f"{self.socket_host}:{self.socket_port}"}
        self.connection_nodes = {}
        if len(sys.argv) == 3:
            self.clone_blockchain(sys.argv[2])
            print(f"Node list: {self.node_address}")
            self.broadcast_message_to_nodes("add_node", self.socket_host+":"+str(self.socket_port))
        # For broadcast block
        self.receive_verified_block = False
        self.start_socket_server()

    def create_genesis_block(self):
        print("Create genesis block...")
        new_block = Block('Hello World!', self.difficulty, 'lkm543', self.miner_rewards)
        new_block.hash = self.get_hash(new_block, 0)
        self.chain.append(new_block)

    def initialize_transaction(self, sender, receiver, amount, fee, message):
        # No need to check balance
        new_transaction = Transaction(sender, receiver, amount, fee, message)
        return new_transaction
    def initialize_did_document(self, id, verificationMethod, authentication):
        new_did_document = DID_document(id, str(verificationMethod), str(authentication))
        return new_did_document
    def transaction_to_string(self, transaction):
        transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'fee': transaction.fee,
            'message': transaction.message
        }
        return str(transaction_dict)
    def did_document_to_string(self, did_document):
        did_document_dict = {
            'id': did_document.id,
            'verificationMethod': did_document.verificationMethod,
            'authentication': did_document.authentication
        }
        return str(did_document_dict)
    def get_transactions_string(self, block):
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction)
        return transaction_str
    def get_did_documents_string(self, block):
        did_document_str = ''
        for did_document in block.did_documents:
            did_document_str += self.did_document_to_string(did_document)
        return did_document_str
    def get_hash(self, block, nonce):
        s = hashlib.sha1()
        s.update(
            (
                block.previous_hash
                + str(block.timestamp)
                + self.get_transactions_string(block)
                + self.get_did_documents_string(block)
                + str(nonce)
            ).encode("utf-8")
        )
        h = s.hexdigest()
        return h

    def add_transaction_to_block(self, block):
        # Get the transaction with highest fee by block_limitation
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)
        if len(self.pending_transactions) > self.block_limitation:
            transcation_accepted = self.pending_transactions[:self.block_limitation]
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:
            transcation_accepted = self.pending_transactions
            self.pending_transactions = []
        block.transactions = transcation_accepted
    def add_did_document_to_block(self, block):
        if len(self.pending_did_documents) > self.block_limitation:
            did_document_accepted = self.pending_did_documents[:self.block_limitation]
            self.pending_did_documents = self.pending_did_documents[self.block_limitation:]
        else:
            did_document_accepted = self.pending_did_documents
            self.pending_did_documents = []
        block.did_documents = did_document_accepted
    def mine_block(self, miner):
        start = time.process_time()

        last_block = self.chain[-1]
        new_block = Block(last_block.hash, self.difficulty, miner, self.miner_rewards)

        self.add_transaction_to_block(new_block)
        self.add_did_document_to_block(new_block)
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.difficulty
        new_block.hash = self.get_hash(new_block, new_block.nonce)
        new_block.nonce = random.getrandbits(32)

        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)
            if self.receive_verified_block:
                print(f"[**] Verified received block. Mine next!")
                self.receive_verified_block = False
                return False

        self.broadcast_block(new_block)

        time_consumed = round(time.process_time() - start, 5)
        print(f"Hash: {new_block.hash} @ diff {self.difficulty}; {time_consumed}s")
        self.chain.append(new_block)

    def adjust_difficulty(self):
        if len(self.chain) % self.adjust_difficulty_blocks != 1:
            return self.difficulty
        elif len(self.chain) <= self.adjust_difficulty_blocks:
            return self.difficulty
        else:
            start = self.chain[-1*self.adjust_difficulty_blocks-1].timestamp
            finish = self.chain[-1].timestamp
            average_time_consumed = round((finish - start) / (self.adjust_difficulty_blocks), 2)
            if average_time_consumed > self.block_time:
                print(f"Average block time:{average_time_consumed}s. Lower the difficulty")
                self.difficulty = 5
            else:
                print(f"Average block time:{average_time_consumed}s. High up the difficulty")
                self.difficulty = 5

    def get_balance(self, account):
        balance = 0
        for block in self.chain:
            # Check miner reward
            miner = False
            if block.miner == account:
                miner = True
                balance += block.miner_rewards
            for transaction in block.transactions:
                if miner:
                    balance += transaction.fee
                if transaction.sender == account:
                    balance -= transaction.amounts
                    balance -= transaction.fee
                elif transaction.receiver == account:
                    balance += transaction.amounts
        return balance
    def get_did_document(self, did):
        document = None
        for block in self.chain:
            for did_document in block.did_documents:
                if did_document.id == did:
                    document = did_document
        if document:
            return self.did_document_to_string(document)
        else:
            return "DID not found!"
                    
    def get_transaction_message(self, account):
        message = []
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.receiver == account and transaction.message!='':
                    message.append(transaction.message)
        return message

    def verify_blockchain(self):
        previous_hash = ''
        for idx,block in enumerate(self.chain):
            if self.get_hash(block, block.nonce) != block.hash:
                print("Error:Hash not matched!")
                return False
            elif previous_hash != block.previous_hash and idx:
                print("Error:Hash not matched to previous_hash")
                return False
            previous_hash = block.hash
        print("Hash correct!")
        return True

    def generate_address(self):
        public, private = rsa.newkeys(512)
        public_key = public.save_pkcs1()
        private_key = private.save_pkcs1()
        return self.get_address_from_public(public_key), \
            self.extract_from_private(private_key)

    def get_address_from_public(self, public):
        address = str(public).replace('\\n','')
        address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        address = address.replace("-----END RSA PUBLIC KEY-----'", '')
        return address

    def extract_from_private(self, private):
        private_key = str(private).replace('\\n','')
        private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
        private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
        return private_key

    def add_transaction(self, transaction, signature):
        public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        public_key += transaction.sender
        public_key += '\n-----END RSA PUBLIC KEY-----\n'
        public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
        transaction_str = self.transaction_to_string(transaction)
        if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):
            return False, "Balance not enough!"
        try:
            # 驗證發送者
            rsa.verify(transaction_str.encode('utf-8'), signature, public_key_pkcs)
            self.pending_transactions.append(transaction)
            return True, "Authorized successfully!"
        except Exception:
            return False, "RSA Verified wrong!"
    def add_did_document(self, did_document, signature):
        verificationMethod = did_document.verificationMethod
        public_n = eval(str(verificationMethod))['publicKeyJwk']['n']
        public_e = eval(str(verificationMethod))['publicKeyJwk']['e']
        public_key = rsa.PublicKey(int(public_n), int(public_e))
        # public_key = public.save_pkcs1()
        did_document_str = self.did_document_to_string(did_document)
        try:
            # 驗證發送者
            rsa.verify(did_document_str.encode('utf-8'), signature, public_key)
            self.pending_did_documents.append(did_document)
            return True, "Authorized successfully!"
        except Exception:
            return False, "RSA Verified wrong!"

    def start(self):
        address, private = self.generate_address()
        print(f"Miner address: {address}")
        print(f"Miner private: {private}")
        if len(sys.argv) < 3:
            self.create_genesis_block()
        while(True):
            self.mine_block(address)
            self.adjust_difficulty()

    def start_socket_server(self):
        t = threading.Thread(target=self.wait_for_socket_connection)
        t.start()

    def wait_for_socket_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.socket_host, self.socket_port))
            s.listen()
            while True:
                conn, address = s.accept()
                client_handler = threading.Thread(
                    target=self.receive_socket_message,
                    args=(conn, address)
                )
                client_handler.start()

    def receive_socket_message(self, connection, address):
        with connection:
            # print(f'Connected by: {address}')
            address_concat = address[0]+":"+str(address[1])
            while True:
                message = b""
                while True:
                    message += connection.recv(4096)
                    if len(message) % 4096:
                        break
                try:
                    parsed_message = pickle.loads(message)
                except Exception:
                    print(f"{message} cannot be parsed")
                if message:
                    if parsed_message["request"] == "get_balance":
                        print("Start to get the balance for client...")
                        address = parsed_message["address"]
                        balance = self.get_balance(address)
                        response = {
                            "address": address,
                            "balance": balance
                        }
                    elif parsed_message["request"] == "get_did_document":
                        print("Start to get the DID document for client...")
                        did = parsed_message["did"]
                        document = self.get_did_document(did)
                        response = {
                            "did": did,
                            "document": document
                        }
                    elif parsed_message["request"] == "get_transaction_message":
                        print("Start to get the transaction message for client...")
                        address = parsed_message["address"]
                        message = self.get_transaction_message(address)
                        response = {
                            "address": address,
                            "message": message
                        }
                    elif parsed_message["request"] == "transaction":
                        print("Start to transaction for client...")
                        new_transaction = parsed_message["data"]
                        result, result_message = self.add_transaction(
                            new_transaction,
                            parsed_message["signature"]
                        )
                        response = {
                            "result": result,
                            "result_message": result_message
                        }
                        if result:
                            self.broadcast_transaction(new_transaction)
                    elif parsed_message["request"] == "generate_did":
                        print("Start to generate DID for client...")
                        new_did_document = parsed_message["data"]
                        result, result_message = self.add_did_document(
                            new_did_document,
                            parsed_message["signature"]
                        )
                        response = {
                            "result": result,
                            "result_message": result_message
                        }
                        if result:
                            self.broadcast_did_document(new_did_document)
                    # 接收到同步區塊的請求
                    elif parsed_message["request"] == "clone_blockchain":
                        print(f"[*] Receive blockchain clone request by {address}...")
                        message = {
                            "request": "upload_blockchain",
                            "blockchain_data": self
                        }
                        connection.sendall(pickle.dumps(message))
                        continue
                    # 接收到挖掘出的新區塊
                    elif parsed_message["request"] == "broadcast_block":
                        print(f"[*] Receive block broadcast by {address}...")
                        self.receive_broadcast_block(parsed_message["data"])
                        continue
                    # 接收到廣播的交易
                    elif parsed_message["request"] == "broadcast_transaction":
                        print(f"[*] Receive transaction broadcast by {address}...")
                        self.pending_transactions.append(parsed_message["data"])
                        continue
                    elif parsed_message["request"] == "broadcast_did_document":
                        print(f"[*] Receive did_document broadcast by {address}...")
                        self.pending_did_documents.append(parsed_message["data"])
                        continue
                    # 接收到新增節點的請求
                    elif parsed_message["request"] == "add_node":
                        print(f"[*] Receive add_node broadcast by {address}...")
                        self.node_address.add(parsed_message["data"])
                        continue
                    else:
                        response = {
                            "message": "Unknown command."
                        }
                    response_bytes = str(response).encode('utf8')
                    connection.sendall(response_bytes)

    def clone_blockchain(self, address):
        print(f"Start to clone blockchain by {address}")
        target_host = address.split(":")[0]
        target_port = int(address.split(":")[1])
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_host, target_port))
        message = {"request": "clone_blockchain"}
        client.send(pickle.dumps(message))
        response = b""
        print(f"Start to receive blockchain data by {address}")
        while True:
            response += client.recv(4096)
            if len(response) % 4096:
                break
        client.close()
        response = pickle.loads(response)["blockchain_data"]

        self.adjust_difficulty_blocks = response.adjust_difficulty_blocks
        self.difficulty = response.difficulty
        self.block_time = response.block_time
        self.miner_rewards = response.miner_rewards
        self.block_limitation = response.block_limitation
        self.chain = response.chain
        self.pending_transactions = response.pending_transactions
        self.pending_did_documents = response.pending_did_documents
        self.node_address.update(response.node_address)

    def broadcast_block(self, new_block):
        self.broadcast_message_to_nodes("broadcast_block", new_block)

    def broadcast_transaction(self, new_transaction):
        self.broadcast_message_to_nodes("broadcast_transaction", new_transaction)
    def broadcast_did_document(self, new_did_document):
        self.broadcast_message_to_nodes("broadcast_did_document", new_did_document)
    def broadcast_message_to_nodes(self, request, data=None):
        address_concat = self.socket_host + ":" + str(self.socket_port)
        message = {
            "request": request,
            "data": data
        }
        for node_address in self.node_address:
            if node_address != address_concat:
                target_host = node_address.split(":")[0]
                target_port = int(node_address.split(":")[1])
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((target_host, target_port))
                client.sendall(pickle.dumps(message))
                client.close()

    def receive_broadcast_block(self, block_data):
        last_block = self.chain[-1]
        # Check the hash of received block
        if block_data.previous_hash != last_block.hash:
            print("[**] Received block error: Previous hash not matched!")
            return False
        elif block_data.difficulty != self.difficulty:
            print("[**] Received block error: Difficulty not matched!")
            return False
        elif block_data.hash != self.get_hash(block_data, block_data.nonce):
            print(block_data.hash)
            print("[**] Received block error: Hash calculation not matched!")
            return False
        else:
            if block_data.hash[0: self.difficulty] == '0' * self.difficulty:
                for transaction in block_data.transactions:
                        self.pending_transactions.remove(transaction)
                for did_document in block_data.did_documents:
                        self.pending_did_documents.remove(did_document)
                self.receive_verified_block = True
                self.chain.append(block_data)
                return True
            else:
                print(f"[**] Received block error: Hash not matched by diff!")
                return False

if __name__ == '__main__':
    block = BlockChain()
    block.start()

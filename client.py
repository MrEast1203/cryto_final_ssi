# -*- coding: utf-8 -*-
import pickle
import socket
import sys
import threading
import time

import rsa
import json
from pprint import pprint

import random
import string
import base64

import uuid
# Shared storage for responses
response_storage = {}
response_received = threading.Event()

def handle_receive():
    while True:
        response = client.recv(4096)
        if response:
            decoded_str = response.decode('utf-8')
            if "did:example:" in decoded_str:
                did_document_dict = eval(eval(decoded_str)['document'])
                did_document_dict['verificationMethod'] = eval(did_document_dict['verificationMethod'])
                did_document_dict['authentication'] = eval(did_document_dict['authentication'])
                response_storage['publicKeyJwk'] = did_document_dict['verificationMethod']['publicKeyJwk']
                pprint(did_document_dict)
                response_received.set()
                with open('did_document.json', 'w') as file:
                    json.dump(did_document_dict, file, indent=4)  # 'indent=4' for pretty printing
            else:
                print(f"[*] Message from node: {response}")

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message

class DID_document:
    def __init__(self, id, verificationMethod, authentication):
        self.id = id
        self.verificationMethod = verificationMethod
        self.authentication = authentication

def generate_address():
    public, private = rsa.newkeys(512)
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()
    return get_address_from_public(public_key), extract_from_private(private_key)

def generate_did():
    public, private = rsa.newkeys(512)
    n = public.n
    e = public.e
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()
    public = get_address_from_public(public_key)
    private = extract_from_private(private_key)
    did_key = {
        'did': "did:example:" + public,
        'private_key': private
    }
    return did_key, n, e
def get_address_from_public(public):
    address = str(public).replace('\\n','')
    address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
    address = address.replace("-----END RSA PUBLIC KEY-----'", '')
    return address

def extract_from_private(private):
    private_key = str(private).replace('\\n','')
    private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
    return private_key

def transaction_to_string(transaction):
    transaction_dict = {
        'sender': str(transaction.sender),
        'receiver': str(transaction.receiver),
        'amounts': transaction.amounts,
        'fee': transaction.fee,
        'message': transaction.message
    }
    return str(transaction_dict)

def did_document_to_string(did_document):
    did_document_dict = {
        'id': did_document.id,
        'verificationMethod': did_document.verificationMethod,
        'authentication': did_document.authentication
    }
    return str(did_document_dict)

def initialize_transaction(sender, receiver, amount, fee, message):
    # No need to check balance
    new_transaction = Transaction(sender, receiver, amount, fee, message)
    return new_transaction
def initialize_did_document(did, n, e):
    verificationMethod = {
        'id': did + '#keys-0', 
        'type': 'JsonWebKey2020',
        'controller': did,
        'publicKeyJwk': {
            'kty': 'RSA',
            'e': e,
            'n': n
        }
    }
    authentication = [verificationMethod['id']]
    new_did_document = DID_document(did, str(verificationMethod), str(authentication))
    return new_did_document
def sign_transaction(transaction, private):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    transaction_str = transaction_to_string(transaction)
    signature = rsa.sign(transaction_str.encode('utf-8'), private_key_pkcs, 'SHA-1')
    return signature

def sign_did_document(did_document, private):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    did_document_str = did_document_to_string(did_document)
    signature = rsa.sign(did_document_str.encode('utf-8'), private_key_pkcs, 'SHA-1')
    return signature

def sign_challenge(challenge, private):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    signature = rsa.sign(challenge.encode('utf-8'), private_key_pkcs, 'SHA-1')
    base64_signature = base64.b64encode(signature).decode()
    return base64_signature

def create_vc(id, holder_did, issuer_did, date, name, degree_type, degree_name, university, GPA):
    vc = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": id,
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": issuer_did,
        "validFrom": date,
        "credentialSubject": {
          "id": holder_did,
          "name": name,
          "degree": {
            "type": degree_type,
            "name": degree_name
          },
          "university": university,
          "GPA": GPA
        }
    }
    return vc
def sign_vc(vc, private):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    vc_str = json.dumps(vc)
    signature = rsa.sign(vc_str.encode('utf-8'), private_key_pkcs, 'SHA-1')
    vc["signature"] = base64.b64encode(signature).decode()
    return vc

if __name__ == "__main__":
    target_host = "127.0.0.1"
    target_port = int(sys.argv[1])
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))

    receive_handler = threading.Thread(target=handle_receive, args=())
    receive_handler.start()

    command_dict = {
        "1": "generate_address",
        "2": "get_balance",
        "3": "transaction",
        "4": "generate_did",
        "5": "get_did_document",
        "6": "did_operation",
        "7": "verify_vc",
        "8": "get_transaction_message"
    }
    did_command_dict = {
        "1": "check_did_holder",
        "2": "sign_challenge",
        "3": "issue_credential",
    }

    while True:
        print("Command list:")
        print("1. generate_address")
        print("2. get_balance")
        print("3. transaction")
        print("4. generate_did")
        print("5. get_did_document")
        print("6. did_operation")
        print("7. verify_vc")
        print("8. get_transaction_message")
        command = input("Command: ")
        if str(command) not in command_dict.keys():
            print("Unknown command.")
            continue
        message = {
            "request": command_dict[str(command)]
        }
        if command_dict[str(command)] == "generate_address":
            address, private_key = generate_address()
            print(f"Address: {address}")
            print(f"Private key: {private_key}")

        elif command_dict[str(command)] == "get_balance":
            address = input("Address: ")
            message['address'] = address
            client.send(pickle.dumps(message))

        elif command_dict[str(command)] == "get_transaction_message":
            did = input("DID: ")
            message['address'] = did.replace("did:example:", "")
            client.send(pickle.dumps(message))

        elif command_dict[str(command)] == "transaction":
            address = input("Address: ")
            private_key = input("Private_key: ")
            receiver = input("Receiver: ")
            amount = input("Amount: ")
            fee = input("Fee: ")
            comment = input("Comment: ")
            new_transaction = initialize_transaction(
                address, receiver, int(amount), int(fee), comment
            )
            signature = sign_transaction(new_transaction, private_key)
            message["data"] = new_transaction
            message["signature"] = signature
            client.send(pickle.dumps(message))

        elif command_dict[str(command)] == "generate_did":
            did_key, n, e = generate_did()
            print(f"DID: {did_key['did']}")
            print(f"Private key: {did_key['private_key']}")
            new_did_document = initialize_did_document(did_key['did'], n, e)
            signature = sign_did_document(new_did_document, did_key['private_key'])
            message["data"] = new_did_document
            message["signature"] = signature
            client.send(pickle.dumps(message))

        elif command_dict[str(command)] == "get_did_document":
            did = input("DID: ")
            message['did'] = did
            client.send(pickle.dumps(message))

        elif command_dict[str(command)] == "did_operation":
            did = input("DID: ")
            private_key = input("Private_key: ")
            print("Command list:")
            print("1. check_did_holder")
            print("2. sign_challenge")
            print("3. issue_credential")
            operation = input("Operation: ")
            if str(operation) not in did_command_dict.keys():
                print("Unknown command.")
                continue
            if did_command_dict[str(operation)] == "check_did_holder":
                holder_did = input("Holder DID: ")
                # Define the character pool: uppercase letters and digits
                char_pool = string.ascii_uppercase + string.digits
                # Generate a 6-character random string
                challenge = ''.join(random.choices(char_pool, k=6))
                client.send(pickle.dumps({'request': 'get_did_document', 'did': holder_did}))
                # Wait for the response
                response_received.wait()
                publicKeyJwk = response_storage['publicKeyJwk']
                print('Public key: ', type(publicKeyJwk), publicKeyJwk)
                public_key = rsa.PublicKey(publicKeyJwk['n'], publicKeyJwk['e'])
                print('This is the challenge for holder: ',challenge)
                signed_challenge = input("Signed challenge: ")
                signed_challenge = base64.b64decode(signed_challenge.encode())
                if rsa.verify(challenge.encode('utf-8'), signed_challenge, public_key):
                    print("Success, Holder is verified.")
                else:
                    print("Error, Holder is not verified.")
            elif did_command_dict[str(operation)] == "sign_challenge":
                challenge = input("Challenge: ")
                signed_challenge = sign_challenge(challenge, private_key)
                print("Signed challenge:", signed_challenge)
            elif did_command_dict[str(operation)] == "issue_credential":
                holder_did = input("Holder DID: ")
                name = input("Name: ")
                university = input("University: ")
                degree_type = input("Degree type: ")
                degree_name = input("Degree name: ")
                date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                GPA = input("GPA: ")
                issuer_did = did
                id = str(uuid.uuid4())
                vc = create_vc(id, holder_did, issuer_did, date, name, degree_type, degree_name, university, GPA)
                signed_vc=sign_vc(vc, private_key)
                with open('vc.json', 'w') as file:
                    json.dump(signed_vc, file, indent=4)
                address = did.replace("did:example:", "")
                new_transaction = initialize_transaction(
                    address, address, 0, 0, f"issue_credential: {id}"
                )
                signature = sign_transaction(new_transaction, private_key)
                message["request"] = "transaction"
                message["data"] = new_transaction
                message["signature"] = signature
                client.send(pickle.dumps(message))

            response_received.clear()
        elif command_dict[str(command)] == "verify_vc":
            file_name = input("File name: ")
            with open(file_name, 'r') as file:
                vc = json.load(file)
            signature = vc.pop('signature')
            signature = base64.b64decode(signature.encode())
            issuer_did = vc['issuer']
            issuer_public = issuer_did.replace("did:example:", "")
            issuer_public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
            issuer_public_key += issuer_public
            issuer_public_key += '\n-----END RSA PUBLIC KEY-----\n'
            public_key_pkcs = rsa.PublicKey.load_pkcs1(issuer_public_key.encode('utf-8'))
            if rsa.verify(json.dumps(vc).encode('utf-8'), signature, public_key_pkcs):
                print("Success, VC is verified.")
            else:
                print("Error, VC is not verified.")
        else:
            print("Unknown command.")
        time.sleep(1)

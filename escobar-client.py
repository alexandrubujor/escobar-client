from Crypto.Cipher import AES
import base64
import hashlib
import random
import requests
import json
import sys


import argparse

STRING_FOR_KEYS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@[]^_`{|}~'


def encrypt(plaintext, key):
    cryptor = AES.new(key, AES.MODE_ECB)
    return cryptor.encrypt(plaintext)


def decrypt(ciphertext, key):
    cryptor = AES.new(key, AES.MODE_ECB)
    return cryptor.decrypt(ciphertext)


def align_data(plaintext):
    l = len(plaintext)
    padding_len = 16 - (l % 16)
    padding = ''.join([" " for i in range(padding_len)])
    return ''.join([plaintext, padding])


def b64_encrypt(plaintext_b64, key):
    plaintext = base64.b64decode(plaintext_b64)
    ciphertext = encrypt(plaintext, key)
    return base64.b64encode(ciphertext)


def hash_sum(content_b64):
    content = base64.b64decode(content_b64)
    hash_string = hashlib.sha256(content).hexdigest()
    return hash_string


def plain_text_encrypt_b64(plaintext_string, key_string):
    aligned_text = align_data(plaintext_string)
    first_encryption = encrypt(aligned_text.encode('ASCII'), key_string.encode('ASCII'))
    return base64.b64encode(first_encryption)


def encrypt_message(message):
    text_message = message
    local_key = ''.join(random.choices(STRING_FOR_KEYS, k=32))
    print("Local key is: {}".format(local_key))
    first_encryption = plain_text_encrypt_b64(text_message, local_key)
    return first_encryption.decode('ASCII')


def decrypt_message(message_b64, local_key, remote_key):
    final_message = message_b64
    first_decrypt = decrypt(base64.b64decode(final_message), remote_key.encode('ASCII'))
    second_decrypt = decrypt(first_decrypt, local_key.encode('ASCII'))
    message = second_decrypt.decode('ASCII')
    print(message)


def post_cryptomessage(first_encryption, url, token):
    data = {"content" : first_encryption}
    if token is not None:
        headers = {"Authorization": "Token {}".format(token)}
    else:
        headers = {}
    r = requests.post("{}/api/v1/cryptomessages/new/".format(url), json=data, headers=headers)
    response_data = json.loads(r.text)
    print("Remote key: {}".format(response_data.get('remote_key')))
    print("Retrieve message URL: {}/api/v1/cryptomessages/get/{}/".format(url, response_data.get('hash_sum')))


def get_cryptomesage(message_url):
    r = requests.get(message_url)
    response_data = json.loads(r.text)
    return response_data.get('content')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", type=str, choices=["encrypt", "decrypt"],
                        help="Command to execute")
    parser.add_argument("--local-key", type=str,
                        help="Local encryption key")
    parser.add_argument("--remote-key", type=str,
                        help="Remote encryption key")
    parser.add_argument("--url", type=str, default=None,
                        help="Url of the api server")
    parser.add_argument("--token", type=str, default=None,
                        help="Token used when uploading the encrypted message")
    args = parser.parse_args()
    if args.command == "encrypt":
        print("Encrypting message operation")
        message = sys.stdin.read()
        first_encryption = encrypt_message(message)
        if args.url is not None:
            try:
                post_cryptomessage(first_encryption, args.url, args.token)
            except Exception as e:
                print("Something went wrong while processing your command: {}".format(e))
    elif args.command == "decrypt":
        print("Decrypting message operation")
        if args.url is None:
            message_b64 = input()
        else:
            message_b64 = get_cryptomesage(args.url)
        try:
            decrypt_message(message_b64, local_key=args.local_key, remote_key=args.remote_key)
        except Exception as e:
            print("Something went wrong while processing your command: {}".format(e))


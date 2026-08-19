import rsa
from base64 import b64encode, b64decode

def xor_encrypt(data, key):
    # XOR encryption
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
    return bytes(encrypted_data)

def xor_decrypt(data, key):
    # XOR decryption
    decrypted_data = bytearray()
    for i in range(len(data)):
        decrypted_data.append(data[i] ^ key[i % len(key)])
    return bytes(decrypted_data)

def encode_key(key, private_key=None):
    if private_key:
        encrypted_private_key = xor_encrypt(private_key, key.encode('utf-8'))
        return private_key, b64encode(encrypted_private_key).decode('utf-8')
    else:
        # Generate RSA key pair
        public_key, private_key = rsa.newkeys(2048)
        # Serialize and encrypt the private key
        encrypted_private_key = xor_encrypt(private_key.save_pkcs1(), key.encode('utf-8'))
        return public_key.save_pkcs1().decode('utf-8'), b64encode(encrypted_private_key).decode('utf-8')

def decode_key(private_key_enc, key):
    # Decrypt the private key using XOR decryption
    decrypted_private_key = xor_decrypt(b64decode(private_key_enc), key.encode('utf-8'))
    return bytes(decrypted_private_key)

def encode_data(data, public_key):
    public_key = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
    encrypted_data = rsa.encrypt(data.encode('utf-8'), public_key)
    return b64encode(encrypted_data).decode('utf-8')

def decode_data(data, private_key):
    private_key = rsa.PrivateKey.load_pkcs1(private_key)
    decrypted_data = rsa.decrypt(b64decode(data), private_key)
    return decrypted_data.decode('utf-8')

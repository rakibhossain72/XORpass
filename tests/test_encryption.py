import pytest
import encryption

def test_key_encoding_decoding():
    password = "MyMasterPassword123!"
    pub_key, enc_priv_key = encryption.encode_key(password)

    assert pub_key is not None
    assert "BEGIN RSA PUBLIC KEY" in pub_key or "BEGIN PUBLIC KEY" in pub_key
    assert enc_priv_key is not None

    dec_priv_key_bytes = encryption.decode_key(enc_priv_key, password)
    assert dec_priv_key_bytes is not None
    assert b"RSA PRIVATE KEY" in dec_priv_key_bytes or b"PRIVATE KEY" in dec_priv_key_bytes

def test_data_encryption_decryption():
    password = "MyMasterPassword123!"
    pub_key, enc_priv_key = encryption.encode_key(password)

    secret_text = "SuperSecretPassword2026!"
    encrypted_data = encryption.encode_data(secret_text, pub_key)
    assert encrypted_data != secret_text

    dec_priv_key = encryption.decode_key(enc_priv_key, password)
    decrypted_text = encryption.decode_data(encrypted_data, dec_priv_key)
    assert decrypted_text == secret_text

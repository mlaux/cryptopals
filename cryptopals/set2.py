import cryptopals.set1
import itertools
import os
import random

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(message, block_size):
    diff = ((len(message) // block_size) + 1) * block_size - len(message)
    padding = bytearray(itertools.repeat(diff, diff))
    return bytes(message + padding)


def encrypt_aes_ecb(b, key):
    print(b)
    b = pkcs7_pad(b, 16)
    return _encrypt_aes_ecb(b, key)


def _encrypt_aes_ecb(b, key):
    cipher = Cipher(AES(key), ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b) + encryptor.finalize()


def encrypt_aes_cbc(b, iv, key):
    print(b)
    b = pkcs7_pad(b, 16)
    ciphertext = bytearray()
    blocks = (b[k:k + 16] for k in range(0, len(b), 16))
    previous = iv
    for block in blocks:
        block = cryptopals.set1.fixed_xor(block, previous)
        block = _encrypt_aes_ecb(block, key)
        ciphertext.extend(block)
        previous = block
    return bytes(ciphertext)


def decrypt_aes_cbc(b, iv, key):
    plaintext = bytearray()
    blocks = (b[k:k + 16] for k in range(0, len(b), 16))
    previous = iv
    for block in blocks:
        before_dec = block
        block = cryptopals.set1.decrypt_aes_ecb(block, key)
        block = cryptopals.set1.fixed_xor(block, previous)
        previous = before_dec
        plaintext.extend(block)
    return bytes(plaintext)


def is_ecb(enc_func):
    result = enc_func(bytes(itertools.repeat(0x41, 64)))
    return result[16:32] == result[32:48]

import cryptopals.set1
import itertools
import base64
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
    b = pkcs7_pad(b, 16)
    return _encrypt_aes_ecb(b, key)


def _encrypt_aes_ecb(b, key):
    cipher = Cipher(AES(key), ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b) + encryptor.finalize()


def encrypt_aes_cbc(b, iv, key):
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
    return result[:16] == result[16:32]


def ecb_with_unknown_string(b):
    key = b'\x1e\xd3VLH\x94\xd8\xe7]y\xa0\xb2\xbd\x99\xf0\x1f'
    unknown_string = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcy' \
                     'BvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    return encrypt_aes_ecb(b + base64.b64decode(unknown_string), key)


def break_ecb():
    largest_enc_size = 0
    block_size = 0
    for possible_block_size in range(1, 10):
        x = ecb_with_unknown_string(bytes(itertools.repeat(0x41, possible_block_size)))
        if len(x) > largest_enc_size:
            if largest_enc_size != 0:
                block_size = len(x) - largest_enc_size
                break
            largest_enc_size = len(x)

    assert(block_size == 16)
    assert(is_ecb(ecb_with_unknown_string))

    almost_block = bytes(itertools.repeat(0x41, block_size - 1))
    possible_blocks = {}
    for last_char in range(32, 127):
        block = almost_block + bytes((last_char,))
        enc = ecb_with_unknown_string(block)[:16]
        possible_blocks[enc] = block
    result = ecb_with_unknown_string(almost_block)
    print(possible_blocks[result[:16]])

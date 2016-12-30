import base64
import functools
import os
import unittest
import itertools
import cryptopals.set2


class Set2Test(unittest.TestCase):

    def test_pkcs7_pad(self):
        message = b'YELLOW SUBMARINE'
        expected_result = b'YELLOW SUBMARINE\x04\x04\x04\x04'
        self.assertEqual(expected_result, cryptopals.set2.pkcs7_pad(message, 20))

    def test_decrypt_aes_cbc(self):
        with open('output/challenge10.txt') as f:
            expected_result = f.read().encode('utf-8')
        with open('input/challenge10.txt') as f:
            test_input = base64.b64decode(f.read())
        iv = bytes(itertools.repeat(0, 16))
        actual_result = cryptopals.set2.decrypt_aes_cbc(test_input, iv, b'YELLOW SUBMARINE')
        self.assertEqual(expected_result, actual_result)

    def test_is_ecb(self):
        self.assertTrue(cryptopals.set2.is_ecb(
                functools.partial(cryptopals.set2.encrypt_aes_ecb, key=os.urandom(16))))
        self.assertFalse(cryptopals.set2.is_ecb(
                functools.partial(cryptopals.set2.encrypt_aes_cbc, iv=os.urandom(16), key=os.urandom(16))))

    def test_break_ecb(self):
        self.assertTrue(cryptopals.set2.is_ecb(cryptopals.set2.ecb_with_unknown_string))
        cryptopals.set2.break_ecb()
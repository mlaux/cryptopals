import base64
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

import unittest
import cryptopals.set1


class Set1Test(unittest.TestCase):

    def test_hex_to_b64(self):
        test_hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        result = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(result, cryptopals.set1.hex_to_b64(test_hex))

    def test_fixed_xor(self):
        a = '1c0111001f010100061a024b53535009181c'
        b = '686974207468652062756c6c277320657965'
        c = cryptopals.set1.fixed_xor(a, b)
        self.assertEqual(b'746865206b696420646f6e277420706c6179', c)

    def test_break_single_byte_xor(self):
        inp = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        expected = b'Cooking MC\'s like a pound of bacon'
        result, _, _ = cryptopals.set1.break_single_byte_xor(inp)
        self.assertEqual(expected, result)

    def test_detect_single_byte_xor(self):
        result = cryptopals.set1.detect_single_byte_xor('input/challenge4.txt')
        self.assertEqual(b'Now that the party is jumping\n', result)

    def test_repeating_key_xor(self):
        inp = 'Burning \'em, if you ain\'t quick and nimble\n' \
              'I go crazy when I hear a cymbal'
        cryptopals.set1.repeating_key_xor(inp, b'ICE')

    def test_break_repeating_key_xor(self):
        with open('output/challenge6.txt') as f:
            expected_result = f.read().encode('utf-8')
        actual_result = cryptopals.set1.break_repeating_key_xor('input/challenge6.txt')
        self.assertEqual(expected_result, actual_result)

    def test_decrypt_aes_ecb(self):
        with open('output/challenge7.txt') as f:
            expected_result = f.read().encode('utf-8')
        actual_result = cryptopals.set1.decrypt_aes_ecb('input/challenge7.txt', b'YELLOW SUBMARINE')
        self.assertEqual(expected_result, actual_result)

    def test_detect_aes_ecb(self):
        expected = b'\xd8\x80a\x97@\xa8\xa1\x9bx@\xa8\xa3\x1c\x81\n=\x08d\x9a\xf7\r\xc0oO\xd5\xd2\xd6\x9ctL\xd2\x83' \
                   b'\xe2\xdd\x05/kd\x1d\xbf\x9d\x11\xb04\x85B\xbbW\x08d\x9a\xf7\r\xc0oO\xd5\xd2\xd6\x9ctL\xd2\x83' \
                   b'\x94u\xc9\xdf\xdb\xc1\xd4e\x97\x94\x9d\x9c~\x82\xbfZ\x08d\x9a\xf7\r\xc0oO\xd5\xd2\xd6\x9ctL\xd2' \
                   b'\x83\x97\xa9>\xab\x8dj\xec\xd5fH\x91Tx\x9ak\x03\x08d\x9a\xf7\r\xc0oO\xd5\xd2\xd6\x9ctL\xd2\x83' \
                   b'\xd4\x03\x18\x0c\x98\xc8\xf6\xdb\x1f*?\x9c@@\xde\xb0\xabQ\xb2\x993\xf2\xc1#\xc5\x83\x86\xb0o' \
                   b'\xba\x18j'
        result = cryptopals.set1.detect_aes_ecb('input/challenge8.txt')
        self.assertEqual(expected, result)

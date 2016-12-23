import base64
import binascii
import itertools

from math import sqrt

"""letter_frequencies = {'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
                      'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
                      'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
                      'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
                      'u': 2.758, 'v': 0.978, 'w': 2.36,  'x': 0.15,  'y': 1.974,
                      'z': 0.074}"""

letter_frequencies = [8.167, 1.492, 2.782, 4.253, 12.702,
                      2.228, 2.015, 6.094, 6.966, 0.153,
                      0.772, 4.025, 2.406, 6.749, 7.507,
                      1.929, 0.095, 5.987, 6.327, 9.056,
                      2.758, 0.978, 2.36,  0.15,  1.974,
                      0.074]


def hex_to_b64(hex_str):
    arr = bytes.fromhex(hex_str)
    return base64.b64encode(arr)


def fixed_xor(a, b):
    a = bytes.fromhex(a)
    b = bytes.fromhex(b)
    c = bytearray((x ^ y for (x, y) in zip(a, b)))

    return binascii.hexlify(c)


def break_single_byte_xor(a):
    return _break_single_byte_xor(bytes.fromhex(a))


def rms_error(a, b):
    error = 0
    for (x, y) in zip(a, b):
        error += (x - y) * (x - y)
    return sqrt(error / len(a))


def _break_single_byte_xor(a):
    letters = b' etaoinshrdlucmwfgypbvkjxqz'[::-1]

    max_score = 0
    best_result = None
    best_key = 0
    for possible_key in range(0, 256):
        fill = itertools.repeat(possible_key, len(a))
        result = bytearray((x ^ y for (x, y) in zip(a, fill)))

        non_ascii = False
        for ch in result:
            if ch >= 127:
                non_ascii = True
        if non_ascii:
            continue

        score = 0
        for ch in result:
            found = letters.find(ch)
            if found != -1:
                score += found

        if score > max_score:
            max_score = score
            best_result = result
            best_key = possible_key

    if best_result is None:
        return None, 0, 0

    return bytes(best_result), max_score, best_key


def detect_single_byte_xor(file):
    max_score = 0
    best_result = None
    for line in open(file):
        line = line[:-1]
        result, score, _ = break_single_byte_xor(line)
        if score > max_score:
            max_score = score
            best_result = result
    return best_result


def repeating_key_xor(a, key):
    result = bytearray((ord(ch) ^ x
                        for (ch, x)
                        in zip(a, itertools.cycle(key))))
    return binascii.hexlify(result)


def count_same_chars(a, b):
    count = 0
    for x, y in zip(a, b):
        if x == y:
            count += 1
    return count


def break_repeating_key_xor(file_name):
    with open(file_name) as file:
        contents = base64.b64decode(file.read())
    best_size_score = 0
    best_size = 0
    for keysize in range(2, 40):
        shifted = contents[keysize:] + contents[:keysize]
        size_score = count_same_chars(contents, shifted)
        if size_score > best_size_score:
            best_size_score = size_score
            best_size = keysize
    blocks = [contents[k:k+best_size] for k in range(0, len(contents), best_size)]
    transpose = itertools.zip_longest(*blocks, fillvalue=0)
    key = ''
    decrypted_blocks = []
    for block in transpose:
        result, score, keypart = _break_single_byte_xor(block)
        if result is None:
            print('wrong key length')
            return None
        key += str(chr(keypart))
        decrypted_blocks.append(result)

    val = b''.join(bytes(n) for n in zip(*decrypted_blocks))
    return bytes(val)

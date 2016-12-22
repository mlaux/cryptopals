import base64
import binascii
import itertools


def hex_to_b64(hex_str):
    arr = bytes.fromhex(hex_str)
    return base64.b64encode(arr)


def fixed_xor(a, b):
    a = bytes.fromhex(a)
    b = bytes.fromhex(b)
    c = bytearray((x ^ y for (x, y) in zip(a, b)))

    return binascii.hexlify(c)


def break_single_byte_xor(a):
    letters = b'zqxjkvbpygfwmucldrhsnioate'
    a = bytes.fromhex(a)
    max_score = 0
    best_result = None
    for possible_key in range(1, 256):
        fill = itertools.repeat(possible_key, len(a))
        result = bytearray((x ^ y for (x, y) in zip(a, fill)))
        score = 0
        for num in result:
            score += letters.find(num)
        if score > max_score:
            max_score = score
            best_result = result

    return bytes(best_result), max_score


def detect_single_byte_xor(file):
    max_score = 0
    best_result = None
    for line in open(file):
        line = line[:-1]
        result, score = break_single_byte_xor(line)
        if score > max_score:
            max_score = score
            best_result = result
    return best_result


def repeating_key_xor(a, key):
    result = bytearray((ord(ch) ^ x
                        for (ch, x)
                        in zip(a, itertools.cycle(key))))
    return binascii.hexlify(result)


def break_repeating_key_xor(file):
    return None

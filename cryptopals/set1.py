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
    return _break_single_byte_xor(bytes.fromhex(a))


def _break_single_byte_xor(a):
    letters = b'zqxjkvbpygfwmucldrhsnioate'
    max_score = 0
    best_result = None
    best_key = 0
    for possible_key in range(0, 256):
        fill = itertools.repeat(possible_key, len(a))
        result = bytearray((x ^ y for (x, y) in zip(a, fill)))
        score = sum(letters.find(num) for num in result)
        if score > max_score:
            max_score = score
            best_result = result
            best_key = possible_key

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


def edit_distance(a, b):
    return sum((bin(x ^ y).count('1') for (x, y) in zip(a, b)))


def break_repeating_key_xor(file_name):
    with open(file_name) as file:
        contents = base64.b64decode(file.read())
    best_size_score = 99999
    best_size = 0
    for keysize in range(2, 40):
        pt1 = contents[0:keysize]
        pt2 = contents[keysize:2*keysize]
        size_score = edit_distance(pt1, pt2) / keysize
        if size_score < best_size_score:
            best_size_score = size_score
            best_size = keysize
    print('keysize is probably', best_size, best_size_score)
    blocks = [contents[k:k+best_size] for k in range(0, len(contents), best_size)]
    transpose = itertools.zip_longest(*blocks, fillvalue=0)
    key = ''
    decrypted_blocks = []
    for block in transpose:
        result, score, keypart = _break_single_byte_xor(block)
        key += str(chr(keypart))
        print(key, score, result)
        decrypted_blocks.append(result)

    val = b''.join(bytes(n) for n in zip(*decrypted_blocks))
    print(val)
    return bytes(val)

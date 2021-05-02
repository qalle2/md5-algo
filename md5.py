"""An implementation of the MD5 algorithm."""

import math, struct, sys

def prepare_message(message):
    # prepare message for hashing

    # append terminator byte, padding and original length in bits modulo 2 ** 64; the new length
    # will be a multiple of 64 bytes
    paddingSize = (64 - 1 - 8 - len(message) % 64) % 64
    lengthInBits = (len(message) * 8) % 2 ** 64
    return message + b"\x80" + paddingSize * b"\x00" + struct.pack("<Q", lengthInBits)

def rol(n, bits):
    # rotate a 32-bit integer left

    return ((n << bits) & 0xffffffff) | ((n & 0xffffffff) >> (32 - bits))

def hash_chunk_slow(state, chunk):
    # hash one chunk (optimized for size)
    # http://en.wikipedia.org/wiki/MD5#Pseudocode
    # state: 4 unsigned 32-bit integers
    # chunk: 16 unsigned 32-bit integers
    # return: 4 unsigned 32-bit integers

    (a, b, c, d) = state

    for r in range(64):
        if r < 16:
            bits = d ^ (b & (c ^ d))
            #bits = (b & c) | (~b & d)  # equivalent
            index = r
            shift = (7, 12, 17, 22)[r & 3]
        elif r < 32:
            bits = c ^ (d & (b ^ c))
            #bits = (d & b) | (c & ~d)  # equivalent
            index = (5 * r + 1) & 15
            shift = (5, 9, 14, 20)[r & 3]
        elif r < 48:
            bits = b ^ c ^ d
            index = (3 * r + 5) & 15
            shift = (4, 11, 16, 23)[r & 3]
        else:
            bits = c ^ (b | ~d)
            index = (7 * r) & 15
            shift = (6, 10, 15, 21)[r & 3]

        const = math.floor(abs(math.sin(r + 1)) * 0x100000000)
        bAdd = (const + a + bits + chunk[index]) & 0xffffffff
        bAdd = rol(bAdd, shift)
        (a, b, c, d) = (d, (b + bAdd) & 0xffffffff, b, c)

    return (a, b, c, d)

def hash_chunk_fast(state, chunk):
    # hash one chunk (optimized for speed)
    # state: 4 unsigned 32-bit integers
    # chunk: 16 unsigned 32-bit integers
    # return: 4 unsigned 32-bit integers

    (a, b, c, d) = state

    # rounds 0-15
    a = a + (d ^ b & (c ^ d)) + chunk[ 0] + 0xd76aa478 & 0xffffffff; a = (a <<  7 | a >> 25) + b
    d = d + (c ^ a & (b ^ c)) + chunk[ 1] + 0xe8c7b756 & 0xffffffff; d = (d << 12 | d >> 20) + a
    c = c + (b ^ d & (a ^ b)) + chunk[ 2] + 0x242070db & 0xffffffff; c = (c << 17 | c >> 15) + d
    b = b + (a ^ c & (d ^ a)) + chunk[ 3] + 0xc1bdceee & 0xffffffff; b = (b << 22 | b >> 10) + c
    a = a + (d ^ b & (c ^ d)) + chunk[ 4] + 0xf57c0faf & 0xffffffff; a = (a <<  7 | a >> 25) + b
    d = d + (c ^ a & (b ^ c)) + chunk[ 5] + 0x4787c62a & 0xffffffff; d = (d << 12 | d >> 20) + a
    c = c + (b ^ d & (a ^ b)) + chunk[ 6] + 0xa8304613 & 0xffffffff; c = (c << 17 | c >> 15) + d
    b = b + (a ^ c & (d ^ a)) + chunk[ 7] + 0xfd469501 & 0xffffffff; b = (b << 22 | b >> 10) + c
    a = a + (d ^ b & (c ^ d)) + chunk[ 8] + 0x698098d8 & 0xffffffff; a = (a <<  7 | a >> 25) + b
    d = d + (c ^ a & (b ^ c)) + chunk[ 9] + 0x8b44f7af & 0xffffffff; d = (d << 12 | d >> 20) + a
    c = c + (b ^ d & (a ^ b)) + chunk[10] + 0xffff5bb1 & 0xffffffff; c = (c << 17 | c >> 15) + d
    b = b + (a ^ c & (d ^ a)) + chunk[11] + 0x895cd7be & 0xffffffff; b = (b << 22 | b >> 10) + c
    a = a + (d ^ b & (c ^ d)) + chunk[12] + 0x6b901122 & 0xffffffff; a = (a <<  7 | a >> 25) + b
    d = d + (c ^ a & (b ^ c)) + chunk[13] + 0xfd987193 & 0xffffffff; d = (d << 12 | d >> 20) + a
    c = c + (b ^ d & (a ^ b)) + chunk[14] + 0xa679438e & 0xffffffff; c = (c << 17 | c >> 15) + d
    b = b + (a ^ c & (d ^ a)) + chunk[15] + 0x49b40821 & 0xffffffff; b = (b << 22 | b >> 10) + c

    # rounds 16-31
    a = a + (c ^ d & (b ^ c)) + chunk[ 1] + 0xf61e2562 & 0xffffffff; a = (a <<  5 | a >> 27) + b
    d = d + (b ^ c & (a ^ b)) + chunk[ 6] + 0xc040b340 & 0xffffffff; d = (d <<  9 | d >> 23) + a
    c = c + (a ^ b & (d ^ a)) + chunk[11] + 0x265e5a51 & 0xffffffff; c = (c << 14 | c >> 18) + d
    b = b + (d ^ a & (c ^ d)) + chunk[ 0] + 0xe9b6c7aa & 0xffffffff; b = (b << 20 | b >> 12) + c
    a = a + (c ^ d & (b ^ c)) + chunk[ 5] + 0xd62f105d & 0xffffffff; a = (a <<  5 | a >> 27) + b
    d = d + (b ^ c & (a ^ b)) + chunk[10] + 0x02441453 & 0xffffffff; d = (d <<  9 | d >> 23) + a
    c = c + (a ^ b & (d ^ a)) + chunk[15] + 0xd8a1e681 & 0xffffffff; c = (c << 14 | c >> 18) + d
    b = b + (d ^ a & (c ^ d)) + chunk[ 4] + 0xe7d3fbc8 & 0xffffffff; b = (b << 20 | b >> 12) + c
    a = a + (c ^ d & (b ^ c)) + chunk[ 9] + 0x21e1cde6 & 0xffffffff; a = (a <<  5 | a >> 27) + b
    d = d + (b ^ c & (a ^ b)) + chunk[14] + 0xc33707d6 & 0xffffffff; d = (d <<  9 | d >> 23) + a
    c = c + (a ^ b & (d ^ a)) + chunk[ 3] + 0xf4d50d87 & 0xffffffff; c = (c << 14 | c >> 18) + d
    b = b + (d ^ a & (c ^ d)) + chunk[ 8] + 0x455a14ed & 0xffffffff; b = (b << 20 | b >> 12) + c
    a = a + (c ^ d & (b ^ c)) + chunk[13] + 0xa9e3e905 & 0xffffffff; a = (a <<  5 | a >> 27) + b
    d = d + (b ^ c & (a ^ b)) + chunk[ 2] + 0xfcefa3f8 & 0xffffffff; d = (d <<  9 | d >> 23) + a
    c = c + (a ^ b & (d ^ a)) + chunk[ 7] + 0x676f02d9 & 0xffffffff; c = (c << 14 | c >> 18) + d
    b = b + (d ^ a & (c ^ d)) + chunk[12] + 0x8d2a4c8a & 0xffffffff; b = (b << 20 | b >> 12) + c

    # rounds 32-47
    a = a + (b ^ c ^ d) + chunk[ 5] + 0xfffa3942 & 0xffffffff; a = (a <<  4 | a >> 28) + b
    d = d + (a ^ b ^ c) + chunk[ 8] + 0x8771f681 & 0xffffffff; d = (d << 11 | d >> 21) + a
    c = c + (d ^ a ^ b) + chunk[11] + 0x6d9d6122 & 0xffffffff; c = (c << 16 | c >> 16) + d
    b = b + (c ^ d ^ a) + chunk[14] + 0xfde5380c & 0xffffffff; b = (b << 23 | b >>  9) + c
    a = a + (b ^ c ^ d) + chunk[ 1] + 0xa4beea44 & 0xffffffff; a = (a <<  4 | a >> 28) + b
    d = d + (a ^ b ^ c) + chunk[ 4] + 0x4bdecfa9 & 0xffffffff; d = (d << 11 | d >> 21) + a
    c = c + (d ^ a ^ b) + chunk[ 7] + 0xf6bb4b60 & 0xffffffff; c = (c << 16 | c >> 16) + d
    b = b + (c ^ d ^ a) + chunk[10] + 0xbebfbc70 & 0xffffffff; b = (b << 23 | b >>  9) + c
    a = a + (b ^ c ^ d) + chunk[13] + 0x289b7ec6 & 0xffffffff; a = (a <<  4 | a >> 28) + b
    d = d + (a ^ b ^ c) + chunk[ 0] + 0xeaa127fa & 0xffffffff; d = (d << 11 | d >> 21) + a
    c = c + (d ^ a ^ b) + chunk[ 3] + 0xd4ef3085 & 0xffffffff; c = (c << 16 | c >> 16) + d
    b = b + (c ^ d ^ a) + chunk[ 6] + 0x04881d05 & 0xffffffff; b = (b << 23 | b >>  9) + c
    a = a + (b ^ c ^ d) + chunk[ 9] + 0xd9d4d039 & 0xffffffff; a = (a <<  4 | a >> 28) + b
    d = d + (a ^ b ^ c) + chunk[12] + 0xe6db99e5 & 0xffffffff; d = (d << 11 | d >> 21) + a
    c = c + (d ^ a ^ b) + chunk[15] + 0x1fa27cf8 & 0xffffffff; c = (c << 16 | c >> 16) + d
    b = b + (c ^ d ^ a) + chunk[ 2] + 0xc4ac5665 & 0xffffffff; b = (b << 23 | b >>  9) + c

    # rounds 48-63
    a = a + (c ^ (b | ~d)) + chunk[ 0] + 0xf4292244 & 0xffffffff; a = (a <<  6 | a >> 26) + b
    d = d + (b ^ (a | ~c)) + chunk[ 7] + 0x432aff97 & 0xffffffff; d = (d << 10 | d >> 22) + a
    c = c + (a ^ (d | ~b)) + chunk[14] + 0xab9423a7 & 0xffffffff; c = (c << 15 | c >> 17) + d
    b = b + (d ^ (c | ~a)) + chunk[ 5] + 0xfc93a039 & 0xffffffff; b = (b << 21 | b >> 11) + c
    a = a + (c ^ (b | ~d)) + chunk[12] + 0x655b59c3 & 0xffffffff; a = (a <<  6 | a >> 26) + b
    d = d + (b ^ (a | ~c)) + chunk[ 3] + 0x8f0ccc92 & 0xffffffff; d = (d << 10 | d >> 22) + a
    c = c + (a ^ (d | ~b)) + chunk[10] + 0xffeff47d & 0xffffffff; c = (c << 15 | c >> 17) + d
    b = b + (d ^ (c | ~a)) + chunk[ 1] + 0x85845dd1 & 0xffffffff; b = (b << 21 | b >> 11) + c
    a = a + (c ^ (b | ~d)) + chunk[ 8] + 0x6fa87e4f & 0xffffffff; a = (a <<  6 | a >> 26) + b
    d = d + (b ^ (a | ~c)) + chunk[15] + 0xfe2ce6e0 & 0xffffffff; d = (d << 10 | d >> 22) + a
    c = c + (a ^ (d | ~b)) + chunk[ 6] + 0xa3014314 & 0xffffffff; c = (c << 15 | c >> 17) + d
    b = b + (d ^ (c | ~a)) + chunk[13] + 0x4e0811a1 & 0xffffffff; b = (b << 21 | b >> 11) + c
    a = a + (c ^ (b | ~d)) + chunk[ 4] + 0xf7537e82 & 0xffffffff; a = (a <<  6 | a >> 26) + b
    d = d + (b ^ (a | ~c)) + chunk[11] + 0xbd3af235 & 0xffffffff; d = (d << 10 | d >> 22) + a
    c = c + (a ^ (d | ~b)) + chunk[ 2] + 0x2ad7d2bb & 0xffffffff; c = (c << 15 | c >> 17) + d
    b = b + (d ^ (c | ~a)) + chunk[ 9] + 0xeb86d391 & 0xffffffff; b = (b << 21 | b >> 11) + c

    return (a, b & 0xffffffff, c, d)

def md5(message):
    # hash a bytestring; return the hash as 16 bytes

    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]  # initial state
    # prepare message and process it in chunks of 64 bytes (16 32-bit integers)
    for chunk in struct.iter_unpack("<16I", prepare_message(message)):
        # hash the chunk; add each 32-bit integer to the corresponding integer in the state
        #hash_ = hash_chunk_slow(state, chunk)
        hash_ = hash_chunk_fast(state, chunk)
        state = [(s + h) & 0xffffffff for (s, h) in zip(state, hash_)]
    return b"".join(struct.pack("<I", s) for s in state)  # final state is the hash

assert md5(b"").hex() == "d41d8cd98f00b204e9800998ecf8427e"
assert md5(b"\x00").hex() == "93b885adfe0da089cdf634904fd59f71"
assert md5(b"\xff").hex() == "00594fd4f42ba43fc1ca0427a0576295"
assert md5(b"ximaz").hex() == "61529519452809720693702583126814"
assert md5(b"cbaabcdljdac").hex() == "cadbfdfecdcdcdacdbbbfadbcccefabd"
assert md5(55 * b"a").hex() == "ef1772b6dff9a122358552954ad0df65"
assert md5(56 * b"a").hex() == "3b0c8ac703f828b04c6c197006d17218"
assert md5(57 * b"a").hex() == "652b906d60af96844ebd21b674f35e93"
assert md5(63 * b"a").hex() == "b06521f39153d618550606be297466d5"
assert md5(64 * b"a").hex() == "014842d480b571495a4a0363793f7367"
assert md5(65 * b"a").hex() == "c743a45e0d2e6a95cb859adae0248435"
assert md5(bytes(range(256))).hex() == "e2c865db4162bed963bfaa9ef6ac18f0"
assert md5(100 * b"abc").hex() == "f571117acbd8153c8dc3c81b8817773a"

if len(sys.argv) != 2:
    sys.exit("Computes the MD5 hash of a bytestring. Argument: bytestring_in_hexadecimal")
try:
    message = bytes.fromhex(sys.argv[1])
except ValueError:
    sys.exit("Error: invalid argument.")
print(md5(message).hex())

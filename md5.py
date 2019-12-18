"""An implementation of the MD5 algorithm."""

import math
import struct
import sys

def prepare_message(message):
    """Prepare message for hashing."""

    # append terminator byte, padding and original length in bits modulo 2 ** 64; the new length
    # will be a multiple of 64 bytes
    paddingSize = (64 - 1 - 8 - len(message) % 64) % 64
    lengthInBits = (len(message) * 8) % 2 ** 64
    return message + b"\x80" + paddingSize * b"\x00" + struct.pack("<Q", lengthInBits)

def rotate_left(n, amount):
    """Rotate a 32-bit integer left."""

    return ((n << amount) & 0xffff_ffff) | (n >> (32 - amount))

def hash_chunk(state, chunk):
    """Hash one chunk.
    state: 4 unsigned 32-bit integers
    chunk: 16 unsigned 32-bit integers
    return: 4 unsigned 32-bit integers"""

    (a, b, c, d) = state

    for i in range(64):
        if i < 16:
            bits = (b & c) | (~b & d)
            index = i
            shift = (7, 12, 17, 22)[i % 4]
        elif i < 32:
            bits = (d & b) | (c & ~d)
            index = (5 * i + 1) % 16
            shift = (5, 9, 14, 20)[i % 4]
        elif i < 48:
            bits = b ^ c ^ d
            index = (3 * i + 5) % 16
            shift = (4, 11, 16, 23)[i % 4]
        else:
            bits = c ^ (b | ~d)
            index = 7 * i % 16
            shift = (6, 10, 15, 21)[i % 4]

        const = math.floor(abs(math.sin(i + 1)) * 2 ** 32)
        bAdd = (const + a + bits + chunk[index]) & 0xffff_ffff
        bAdd = rotate_left(bAdd, shift)

        (a, b, c, d) = (d, (b + bAdd) & 0xffff_ffff, b, c)

    return (a, b, c, d)

def md5(message):
    """Hash a bytestring. Return the hash as 16 bytes. See references."""

    # set initial state
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    # prepare message and process it in chunks of 64 bytes (16 32-bit integers)
    for chunk in struct.iter_unpack("<16I", prepare_message(message)):
        # hash the chunk; add each 32-bit integer to the corresponding integer in the state
        hash_ = hash_chunk(state, chunk)
        state = [(s + h) & 0xffff_ffff for (s, h) in zip(state, hash_)]
    # the final state is the hash
    return b"".join(struct.pack("<I", number) for number in state)

def main():
    """The main function."""

    if len(sys.argv) != 2:
        sys.exit("Error: invalid number of arguments.")
    message = sys.argv[1]
    try:
        message = bytes.fromhex(message)
    except ValueError:
        sys.exit("Error: invalid argument.")
    print(md5(message).hex())

assert md5(b"").hex() == "d41d8cd98f00b204e9800998ecf8427e"
assert md5(b"\x00").hex() == "93b885adfe0da089cdf634904fd59f71"
assert md5(b"\xff").hex() == "00594fd4f42ba43fc1ca0427a0576295"
assert md5(b"ximaz").hex() == "61529519452809720693702583126814"
assert md5(55 * b"a").hex() == "ef1772b6dff9a122358552954ad0df65"
assert md5(56 * b"a").hex() == "3b0c8ac703f828b04c6c197006d17218"
assert md5(57 * b"a").hex() == "652b906d60af96844ebd21b674f35e93"
assert md5(63 * b"a").hex() == "b06521f39153d618550606be297466d5"
assert md5(64 * b"a").hex() == "014842d480b571495a4a0363793f7367"
assert md5(65 * b"a").hex() == "c743a45e0d2e6a95cb859adae0248435"

if __name__ == "__main__":
    main()

import binascii
import math
import struct
import sys

# MD5 constants
INITIAL_STATE = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
BYTES_PER_CHUNK = 64
ORIGINAL_SIZE_BYTE_COUNT = 8  # bytes needed for original message size
PADDING_BYTE = b"\x00"
BITS_PER_BYTE = 8

HELP_TEXT = """\
Computes the MD5 hash of a bytestring without the hashlib module.
Argument: bytestring in hexadecimal (an even number of digits 0-9 and a-f;
"" = zero-length string)\
"""

def _prepare_message(message):
    originalLen = len(message)
    message = bytearray(message)

    # append a "1" bit (and seven "0" bits)
    message.append(0b1000_0000)

    # append "\x00" bytes to make
    #     length_in_bytes + ORIGINAL_SIZE_BYTE_COUNT
    # a multiple of BYTES_PER_CHUNK
    lenRemainder = len(message) % BYTES_PER_CHUNK
    paddingSize = (-ORIGINAL_SIZE_BYTE_COUNT - lenRemainder) % BYTES_PER_CHUNK
    message += paddingSize * PADDING_BYTE

    # append original length in bits modulo 2**64 (eight little-endian bytes)
    originalLenInBits = (originalLen * BITS_PER_BYTE) & 0xffff_ffff_ffff_ffff
    return message + struct.pack("<Q", originalLenInBits)

def _generate_chunks(message):
    """Prepare the message and generate it in chunks of 16 unsigned 32-bit
    little-endian integers (64 bytes, 512 bits)."""
    for chunk in struct.iter_unpack("<16I", _prepare_message(message)):
        yield chunk

def _hash_chunk(state, chunk):
    """Hash one chunk.
    state: 4 unsigned 32-bit integers
    chunk: 16 unsigned 32-bit integers
    return: 4 unsigned 32-bit integers
    """

    (a, b, c, d) = state

    for i in range(64):
        const = math.floor(abs(math.sin(i + 1)) * 2**32)

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

        bAdd = (const + a + bits + chunk[index]) & 0xffff_ffff
        bAdd = ((bAdd << shift) & 0xffff_ffff) | (bAdd >> (32 - shift))

        a = d
        d = c
        c = b
        b = (b + bAdd) & 0xffff_ffff

    return (a, b, c, d)

def hash(message):
    """Hash a string of bytes. Return the hash as 16 bytes.
    http://en.wikipedia.org/wiki/MD5#Pseudocode"""
    state = list(INITIAL_STATE)
    for chunk in _generate_chunks(message):
        hash = _hash_chunk(state, chunk)
        state = [(s + h) & 0xffff_ffff for (s, h) in zip(state, hash)]
    return b"".join(struct.pack("<I", number) for number in state)

def hexadecimal_hash(message):
    """Hash a string of bytes. Return hash in hexadecimal."""
    return binascii.hexlify(hash(message)).decode("ascii")

def main():
    if len(sys.argv) != 2:
        exit(HELP_TEXT)

    message = sys.argv[1]
    try:
        message = binascii.unhexlify(message)
    except binascii.Error:
        exit("Error: invalid hexadecimal string of bytes.")

    print(hexadecimal_hash(message))

assert hexadecimal_hash(b"")       == "d41d8cd98f00b204e9800998ecf8427e"
assert hexadecimal_hash(b"\x00")   == "93b885adfe0da089cdf634904fd59f71"
assert hexadecimal_hash(b"\xff")   == "00594fd4f42ba43fc1ca0427a0576295"
assert hexadecimal_hash(b"ximaz")  == "61529519452809720693702583126814"
assert hexadecimal_hash(55 * b"a") == "ef1772b6dff9a122358552954ad0df65"
assert hexadecimal_hash(56 * b"a") == "3b0c8ac703f828b04c6c197006d17218"
assert hexadecimal_hash(57 * b"a") == "652b906d60af96844ebd21b674f35e93"
assert hexadecimal_hash(63 * b"a") == "b06521f39153d618550606be297466d5"
assert hexadecimal_hash(64 * b"a") == "014842d480b571495a4a0363793f7367"
assert hexadecimal_hash(65 * b"a") == "c743a45e0d2e6a95cb859adae0248435"

if __name__ == "__main__":
    main()

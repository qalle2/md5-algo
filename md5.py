"""An implementation of the MD5 algorithm."""

import math, struct, sys

def _pad_message(message):
    # append terminator byte, padding and original length in bits modulo 2 ** 64;
    # the new length will be a multiple of 64 bytes (512 bits)
    paddingSize = (64 - 1 - 8 - len(message) % 64) % 64
    lengthInBits = (len(message) * 8) % 2 ** 64
    return message + b"\x80" + paddingSize * b"\x00" + struct.pack("<Q", lengthInBits)

def _rotate_left(n, bits):
    # rotate a 32-bit integer left
    return ((n << bits) & 0xffffffff) | (n >> (32 - bits))

def _hash_chunk(state, chunk):
    # hash one chunk
    # http://en.wikipedia.org/wiki/MD5#Pseudocode
    # state: 4 * 32-bit int (128 bits)
    # chunk: 16 * 32-bit int (512 bits)
    # return: 4 * 32-bit int (128 bits)

    (a, b, c, d) = state

    for r in range(64):
        if r < 16:
            bits = d ^ (b & (c ^ d))  # = (b & c) | (~b & d)
            index = r
            shift = (7, 12, 17, 22)[r & 3]
        elif r < 32:
            bits = c ^ (d & (b ^ c))  # = (b & d) | (c & ~d)
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
        bAdd = _rotate_left(bAdd, shift)
        (a, b, c, d) = (d, (b + bAdd) & 0xffffffff, b, c)

    return (a, b, c, d)

def md5(message):
    """Hash a bytestring. Return the hash as 16 bytes."""

    # initialize state of algorithm (4 * 32 bits = 128 bits)
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    # pad message to a multiple of 512 bits
    message = _pad_message(message)

    # add the hash of each 512-bit (16 * 32-bit) chunk to the state
    for chunk in struct.iter_unpack("<16I", message):
        hash_ = _hash_chunk(state, chunk)
        state = [(s + h) & 0xffffffff for (s, h) in zip(state, hash_)]

    # final state = hash of entire message
    return struct.pack("<4I", *state)

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

def main():
    if len(sys.argv) != 2:
        sys.exit("Compute the MD5 hash of a bytestring. Argument: bytestring_in_hexadecimal")
    try:
        message = bytes.fromhex(sys.argv[1])
    except ValueError:
        sys.exit("Error: invalid argument.")
    print(md5(message).hex())

if __name__ == "__main__":
    main()

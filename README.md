# md5-algo
Computes the MD5 hash of a string of bytes.

Developed with Python 3 under 64-bit Windows.

## Command line arguments
Syntax: *bytestring*

### *bytestring*
* zero or more bytes in hexadecimal
* an even number of digits `0`&ndash;`9` and `a`&ndash;`f`

## Example
Hash the ASCII string `password` (bytes `0x70` `0x61` `0x73` `0x73` `0x77` `0x6f` `0x72` `0x64`):
```
python md5.py 70617373776f7264
5f4dcc3b5aa765d61d8327deb882cf99
```

## References
* [Wikipedia &ndash; MD5 &ndash; pseudocode](http://en.wikipedia.org/wiki/MD5#Pseudocode)

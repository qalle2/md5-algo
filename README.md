# md5-algo
Compute the MD5 hash of a bytestring. Argument: bytestring_in_hexadecimal

## Examples
From command line:
```
$ python3 md5.py 70617373776f7264
5f4dcc3b5aa765d61d8327deb882cf99
```
From Python:
```
from md5 import md5
print(md5(b"password").hex())  # 5f4dcc3b5aa765d61d8327deb882cf99
```

import json, os, binascii, hashlib
username="user1"; password="123"; iterations=260000
salt=binascii.hexlify(os.urandom(16)).decode()
dk=hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
hexd=binascii.hexlify(dk).decode()
stored=f"pbkdf2:sha256:{iterations}${salt}${hexd}"
print(stored)
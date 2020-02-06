import requests
import json
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
#    ctr = Counter.new(128, initial_value=int_of_string(iv))
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.decrypt(ciphertext[16:])

def do_login(server, port, username, password):
    url = "http://" + server + ":" + port + "/api/login"
    hashed_username = hashlib.sha1(username.encode('utf-8')).hexdigest()
    hashed_password = hashlib.sha1((password + hashed_username[0:4]).encode('utf-8')).hexdigest()
    data = { "username": hashed_username }
    res = requests.post(url, data=json.dumps(data))
    if res.status_code != 200:
        print("Error: cannot login")
        return
    else:
        resp = json.loads(res._content.decode('utf-8'))
        if resp["result"]["result"] != "E_OK":
            print(resp["result"]["text"])
        else:
            print(resp["token"])
            print(resp["serialKey"])
            plaintext = decrypt_message(hashed_password, resp["serialKey"].encode('ascii'))
            print(plaintext)

    
#---------------

do_login("localhost", "8080", "test", "test")


import requests
import json
import hashlib
import pyaes

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ExampleConnection:
    """Encapsulates the connection to the example application"""
    def __init__(self, server, port):
        self.server = server
        self.port = port
        print("Connecting to " + self.server + ":" + self.port)

    def do_login(self, username, password):
        url = "http://" + self.server + ":" + self.port + "/api/login"
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
                self.token = resp["token"]
                plaintext = pyaes.decrypt_message(hashed_password, resp["serialKey"])
                self.serial = json.loads(plaintext)["serial"]
                self.key = json.loads(plaintext)["key"]
                print("login succeeded")

    def get_window(self, number):
        url = "http://" + self.server + ":" + self.port + "/api/window/" + str(number)
        data = { "token": self.token,
                 "data": pyaes.encrypt_message(self.key,
                                               json.dumps( { "serial": self.serial + 1,
                                                             "token": self.token } ) ) }
        res = requests.post(url, data=json.dumps(data))
        if res.status_code != 200:
            print("Error: cannot post message")
            return
        else:
            print("OK")

    
#---------------

connection = ExampleConnection("localhost", "8080")
connection.do_login("test", "test")
connection.get_window(0)


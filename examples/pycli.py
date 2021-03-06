import requests
import json
import hashlib
import pyaes
import socket
import sys

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ExampleConnection:
    """Encapsulates the connection to the example application"""
    def __init__(self, server, port):
        self.server = server
        self.port = int(port)
        self.token = ""
        self.serial = ""
        self.key = ""
        print("Setting connection target " + self.server + ":" + str(self.port))

    def check(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((self.server, self.port))
        if result == 0:
            return True
        else:
            return False

    def do_login(self, username, password):
        url = "http://" + self.server + ":" + str(self.port) + "/api/login"
        hashed_username = hashlib.sha1(username.encode('utf-8')).hexdigest()
        hashed_password = hashlib.sha1((password + hashed_username[0:4]).encode('utf-8')).hexdigest()
        data = { "username": hashed_username }
        res = requests.post(url, data=json.dumps(data))
        if res.status_code != 200:
            print("Error: cannot login")
            return False
        else:
            resp = json.loads(res._content.decode('utf-8'))
            if resp["result"]["result"] != "E_OK":
                print(resp["result"]["text"])
                return False
            else:
                self.token = resp["token"]
                plaintext = pyaes.decrypt_message(hashed_password, resp["serialKey"])
                self.serial = json.loads(plaintext)["serial"]
                self.key = json.loads(plaintext)["key"]
                print("login succeeded")
                return True

    def do_logout(self):
        self.serial = self.serial + 1
        encrypted_data = pyaes.encrypt_message(self.key, json.dumps( { "serial": self.serial,
                                                                       "token": self.token } ) )
        url = "http://" + self.server + ":" + str(self.port) + "/api/logout"
        data = { "token": self.token, "data":  encrypted_data }
        res = requests.post(url, data=json.dumps(data))
        if res.status_code != 200:
            print("Error: cannot post message")
            return False
        else:
            if json.loads(res._content.decode('utf-8'))["result"]["result"] == "E_OK":
                return True
            else:
                return False

    def get_window(self, number):
        self.serial = self.serial + 1
        encrypted_data = pyaes.encrypt_message(self.key, json.dumps( { "serial": self.serial,
                                                                       "token": self.token } ) )
        url = "http://" + self.server + ":" + str(self.port) + "/api/window/" + str(number)
        data = { "token": self.token, "data":  encrypted_data }
        res = requests.post(url, data=json.dumps(data))
        if res.status_code != 200:
            print("Error: cannot post message")
            return False
        else:
            return json.loads(res._content.decode('utf-8'))

    def send_message(self, operation, url):
        self.serial = self.serial + 1
        encrypted_data = pyaes.encrypt_message(self.key, json.dumps( { "serial": self.serial,
                                                                       "token": self.token,
                                                                       "operation": operation } ) )
        url = "http://" + self.server + ":" + str(self.port) + url
        data = { "token": self.token, "data":  encrypted_data }
        res = requests.post(url, data=json.dumps(data))
        if res.status_code != 200:
            print("Error: cannot post message")
            return False
        else:
            if json.loads(res._content)["result"]["result"] == "E_OK":
                return pyaes.decrypt_message(self.key, json.loads(res._content)["data"])
            else:
                return json.loads(res._content)["result"]

    def send_pushme(self):
        return self.send_message("post", "/api/application/pushme")

    def get_config(self, url):
        return self.send_message("get", url)



#---------------

connection = ExampleConnection("localhost", "8080")
if connection.check() is False:
    sys.exit("Cannot connect to the server")
if connection.do_login("test", "test") is True:
    #window = connection.get_window(0)
    # print(window["result"])
    #connection.send_pushme()
    print(connection.get_config("/api/config/users"))
    print(connection.get_config("/api/config/session"))
    print(connection.get_config("/api/config/pending"))
    connection.do_logout()

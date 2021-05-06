# -*- coding: utf-8 -*-
"""
Created on Thu Mar 18 20:44:02 2021

@author: mhamz
"""
from datetime import datetime
import socket 
import threading
import random
import string
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5
from PIL import Image   
import ast    
import hashlib
from hashlib import sha512
import time
"""
from tkinter import *

root = Tk()
e = Entry(root, width=50)
e.pack()
def myClick():
    myLabel = Label(root, text="My please ")
    #myLabel.pack()
#myButton = Button(root, text="Click Me!", command=myClick)
#myButton.pack()

root.mainloop()
"""
""" DECLARATION OF ALL THE PORTS NEEDED FOR CONNECTIONS AND THER VARIABLES """

head = 64
pnumu = 5050
pnums = 4040
pnump = 3030
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, pnumu)
ADDRS = (SERVER, pnums)
ADDRP = (SERVER, pnump)
FORMAT = 'utf-8'
SERVER = "192.168.56.1"
random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate pub and priv key
publickey = key.publickey() 
private_key = key.exportKey('PEM')
public_key = publickey.exportKey('PEM')
keyPair = RSA.generate(bits=1024)
#print(keyPair.e)
#print(keyPair.n)


""" TAKE INPUT OF WHAT TO ORDER HERE AND HASH IT """
order = input("Please tell us what you want to buy: ")
order = str(order)
hashedm = int(hashlib.sha1(order.encode("utf-8")).hexdigest(), 16) % (10 ** 8)
hashedm = str(hashedm)
#print(hashedm)

""" CREATE A LISTNENING SERVER """
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
server.settimeout(15)
def listener():
    server.listen()
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=actions, args=(conn, addr))
        thread.start()

def actions(conn, addr):
    purdk = conn.recv(1000)
    conn.send(public_key)
    msgr = conn.recv(2048)
    msgr = msgr.decode("UTF-8")
    print(msgr)
    decrypted = key.decrypt(ast.literal_eval(msgr))
    msgr = decrypted.decode(FORMAT)
    print(msgr)
    conn.close()
    


def padding(msg):
     while (len(msg) !=  1000):
         msg = msg + '|'
     return msg   


def generate_nonce(length=8):
    return ''.join([str(random.randint(0,9)) for i in range(length)])

""" END LISTENING SERVER """
#pdept = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#pdept.connect(ADDRP)
""" KEY EXCHANGE BETWEEN USER AND SUPERVISOR    """
#print(public_key)
supervisor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
supervisor.connect(ADDRS)
supervisor.sendall(public_key)
supkey = supervisor.recv(2000)
#print(supkey)
supkey = RSA.importKey(supkey)
n1 = generate_nonce()
cm = "user " + n1
cm = cm.encode("UTF-8")
ecm = str(supkey.encrypt(cm, 32))
ecm = ecm.encode("UTF-8")
supervisor.sendall(ecm)
#print(type(n1))
retmsg = supervisor.recv(2000)
retmsg = retmsg.decode("UTF-8")
demsgrec = key.decrypt(ast.literal_eval(retmsg))
demsgrec = demsgrec.decode(FORMAT)
name,rn1,n2 = demsgrec.split(" ")
if (name == "supervisor" and rn1 == n1):
    print("Confirmed identity")
#print(demsgrec)
hashedmp = padding(hashedm)
supervisor.sendall(hashedmp.encode("UTF-8"))
keyPairep = padding(str(keyPair.e))
supervisor.sendall((keyPairep.encode("UTF-8")))
#print(keyPair.e)
keyPairnp = padding(str(keyPair.n))
supervisor.sendall(((keyPairnp)).encode("UTF-8"))
msg1 = hashedm
msg1 = msg1.encode("UTF-8")
hash = int.from_bytes(sha512(msg1).digest(), byteorder='big')
signature = pow(hash, keyPair.d, keyPair.n)
signature = str(signature)
print(signature)
signature = str(datetime.now()) + '[{at}]' + signature
signature = padding(signature)
signature = signature.encode("UTF-8")
supervisor.sendall(signature)
order = order.encode('utf-8')
encrypted = str(supkey.encrypt(order, 32))
encrypted = encrypted.encode("UTF-8")
supervisor.send(encrypted)
ver = supervisor.recv(2000)
ver = ver.decode("UTF-8")
#print(ver)
ver = str(ver)
decrypted = key.decrypt(ast.literal_eval(ver))
decrypted = decrypted.decode(FORMAT)
print(decrypted)
#time.sleep(5)

purd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
purd.connect(ADDRP)
#purd.sendall(public_key)
purd.sendall(hashedmp.encode("UTF-8"))
purd.sendall((keyPairep.encode("UTF-8")))
purd.sendall((keyPairnp.encode("UTF-8")))
purd.sendall(signature)
purd.close()

"""
ver = supervisor.recv(2000)
print(ver.decode("UTF-8"))
"""
"""
verdict = supervisor.recv(2000)
print(verdict.decode("UTF-8"))
"""
#print(keyPair.n)
"""
msg1 = "user" + "hash" + order + "hash" + hashedm
msg1 = msg1.encode("UTF-8")
msg1 = str(key.encrypt(msg1, 32))
supervisor.send(msg1.encode("UTF-8"))
"""

""" END KEY EXCHANGE BETWEEN USER AND SUPERVISOR """

"""
msg = "user" + "hash" + order + "hash" + hashedm
supervisor.send(msg.encode("UTF-8"))
orderm = supervisor.recv(2000)
print(orderm)
"""
"""
keyPair = RSA.generate(bits=1024)
print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")
msg = b'A message for signing'
hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
signature = pow(hash, keyPair.d, keyPair.n)
print("Signature:", hex(signature))

msg = b'A message for signing'
hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
hashFromSignature = pow(signature, keyPair.e, keyPair.n)
print("Signature valid:", hash == hashFromSignature)

print(keyPair.d) 
print(type(keyPair.d))
print(keyPair.n)

"""
listener()
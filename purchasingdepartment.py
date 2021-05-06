# -*- coding: utf-8 -*-
"""
Created on Thu Mar 18 20:58:22 2021

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
import hashlib
from hashlib import sha512
import time

head = 64
pnumu = 5050
pnums = 4040
pnump = 3030
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, pnump)
ADDRU = (SERVER, pnumu)
ADDRS = (SERVER, pnums)
FORMAT = 'utf-8'
SERVER = "192.168.56.1"
random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate pub and priv key
publickey = key.publickey() 
private_key = key.exportKey('PEM')
public_key = publickey.exportKey('PEM')
datalist = []
x = 0

def padding(msg):
        while (len(msg) !=  1000):
            msg = msg + '|'
        return msg  
def rempad(msg):
    msg = msg.replace('|', '')
    return msg
def rempad2(msg):
    msg = msg.replace('|', '')
    print("The new msg is: " + msg)
    msg = int(msg)
    return msg


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
def listener():
    server.listen()
    while True:
        conn, addr = server.accept()
        print(conn)
        print(addr)
        thread = threading.Thread(target=actions, args=(conn, addr))
        thread.start()

def actions(conn, addr):
   
    data = conn.recv(1000)
    data = data.decode("UTF-8")
    data = rempad(data)
    data = data.encode("UTF-8")
    print(data)
    datalist.append(data)
    keye = conn.recv(1000)
    keye = keye.decode("UTF-8")
    keye = rempad(keye)
    keye = int(keye)
    print(keye)
    keyn = conn.recv(1000)
    keyn = keyn.decode("UTF-8")
    keyn = rempad(keyn)
    keyn = int(keyn)
    print(keyn)
    signature = conn.recv(1000)
    signature = signature.decode("UTF-8")
    signature = rempad(signature)
    signature = int(signature)
    print(signature)
    usrd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    usrd.connect(ADDRU)
    data = conn.recv(1000)
    data = data.decode("UTF-8")
    data = rempad(data)
    data = data.encode("UTF-8")
    print(data)
    datalist.append(data)
    keye = conn.recv(1000)
    keye = keye.decode("UTF-8")
    keye = rempad(keye)
    keye = int(keye)
    print(keye)
    keyn = conn.recv(1000)
    keyn = keyn.decode("UTF-8")
    keyn = rempad(keyn)
    keyn = int(keyn)
    print(keyn)
    signature = conn.recv(1000)
    signature = signature.decode("UTF-8")
    signature = rempad(signature)
    signature = int(signature)
    print(signature)
    

    """
    hash = int.from_bytes(sha512(data).digest(), byteorder='big')
    hashFromSignature = pow(signature, 65537, keyn)
    print("Signature confirmed:", hash == hashFromSignature)
    if hash == hashFromSignature:
        datalist.append(1)
    if len(datalist) == 4:
        print("Process complete")
    else:
        print("Something failed")
    time.sleep(10)
    print(datalist)
    """
    """
    t = conn.recv(1000)
    t = t.decode("UTF-8")
    t = rempad(t)
    t = t.encode("UTF-8")
    print(t.decode("UTF-8"))
    data = conn.recv(1000)
    print(data.decode("UTF-8"))
    data = data.decode("UTF-8")
    data = rempad(data)
    data = data.encode("UTF-8")
    #print(data)
    keypaire = conn.recv(1000)
    keypairn = conn.recv(1000)
    signature = conn.recv(1000)
    keypaire = keypaire.decode("UTF-8")
    #print(keypaire)
    keypaire = rempad(keypaire)
  
    keypaire = int(keypaire)
    print("THIS IS N ?? " + str(keypaire) + " END IT NOW")
    keypairn = keypairn.decode("UTF-8")
    #print(keypairn)
    keypairn = rempad(keypairn)
    
    keypairn = int(keypairn)
    print("This is " + str(keypairn) + " end it now")
    #print(data.decode("UTF-8"))
    #print(keypaire.decode("UTF-8"))
    #print(keypairn.decode("UTF-8"))
    
    signature = signature.decode("UTF-8")
    #print(signature)
    #print(type(signature))
    #print(len(signature))
    #signature = rempad(signature)
    #print(type(signature))
    #print("WHATS GOING ON???")
    #print(signature)
    
    keypairnact = keypaire 
    signatureact = keypairn
    print(len(str(keypairnact)))
    print(len(str(signatureact)))
    data = t
    print(data)        
    #signature = int(signature)
    hash = int.from_bytes(sha512(data).digest(), byteorder='big')
    hashFromSignature = pow(signatureact, 65537, keypairnact)
    print("Signature confirmed:", hash == hashFromSignature)
    """
    """
    pbuser = conn.recv(1000)
    print(pbuser)
    #userpb = RSA.importKey(pbuser)
    data2 = conn.recv(1000)
    print(data2)
    keye2 = conn.recv(1000)
    keye2 = keye2.decode("UTF-8")
    keye2 = rempad(keye2)
    keye2 = int(keye2)
    keyn2 =  conn.recv(1000)
    keyn2 = keyn2.decode("UTF-8")
    keyn2 = rempad(keyn2)
    keyn2 = int(keyn2)
    sign2 = conn.recv(1000)
    sign2 = sign2.decode("UTF-8")
    sign2 = rempad(sign2)
    sign2 = int(sign2)
    hash2 = int.from_bytes(sha512(data2).digest(), byteorder='big')
    hashFromSignature2 = pow(sign2, 65537, keyn2)
    print("Signature confirmed again from user:", hash2 == hashFromSignature2)
    """

x = 0    
server.settimeout(15)
server.listen(5)    
conn, addr = server.accept()
data = conn.recv(1000)
data = data.decode("UTF-8")
data = rempad(data)
data = data.encode("UTF-8")
#print(data)
datalist.append(data)
keye = conn.recv(1000)
keye = keye.decode("UTF-8")
keye = rempad(keye)
keye = int(keye)
#print(keye)
keyn = conn.recv(1000)
keyn = keyn.decode("UTF-8")
keyn = rempad(keyn)
keyn = int(keyn)
#print(keyn)
signature = conn.recv(1000)
signature = signature.decode("UTF-8")
signature = rempad(signature)
time,signature = signature.split('[{at}]')
signature = int(signature)
print(time)
print(signature)
hash = int.from_bytes(sha512(data).digest(), byteorder='big')
hashFromSignature = pow(signature, keye, keyn)
print("Signature confirmed:", hash == hashFromSignature)
if hash == hashFromSignature:
    x = x + 1
conn.close()
conn, addr = server.accept()
data = conn.recv(1000)
data = data.decode("UTF-8")
data = rempad(data)
data = data.encode("UTF-8")
#print(data)
datalist.append(data)
keye = conn.recv(1000)
keye = keye.decode("UTF-8")
keye = rempad(keye)
keye = int(keye)
#print(keye)
keyn = conn.recv(1000)
keyn = keyn.decode("UTF-8")
keyn = rempad(keyn)
keyn = int(keyn)
#print(keyn)
signature = conn.recv(1000)
signature = signature.decode("UTF-8")
signature = rempad(signature)
time,signature = signature.split('[{at}]')
signature = int(signature)
print(time)
print(signature)
hash = int.from_bytes(sha512(data).digest(), byteorder='big')
hashFromSignature = pow(signature, keye, keyn)
print("Signature confirmed:", hash == hashFromSignature)
if hash == hashFromSignature:
    x = x + 1
if x > 1 and (datalist[0] == datalist[1]):
    print("Both of the signatures are correct and the data matches")
    usrd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    usrd.connect(ADDRU)
    usrd.send(public_key)
    usrk = usrd.recv(1000)
    msg = "The order has been completed"
    msg = msg.encode("UTF-8")
    usrk = RSA.importKey(usrk)
    encrypted = str(usrk.encrypt(msg, 32))
    encrypted = encrypted.encode("UTF-8")
    usrd.send(encrypted)
    
conn.close()



#listener()
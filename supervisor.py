# -*- coding: utf-8 -*-
"""
Created on Thu Mar 18 20:57:59 2021

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
import ast
from hashlib import sha512


head = 64
pnumu = 5050
pnums = 4040
pnump = 3030
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, pnums)
ADDRU = (SERVER, pnumu)
ADDRP = (SERVER, pnump)
items = ["shoes", "clothes", "hats", "belts"]
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
verdict = ""


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
server.settimeout(15)
def listener():
    server.listen()
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=actions, args=(conn, addr))
        thread.start()
def padding(msg):
        while (len(msg) !=  1000):
            msg = msg + '|'
        return msg  
def rempad(msg):
    msg = msg.replace('|', '')
    return msg

def generate_nonce(length=8):
    return ''.join([str(random.randint(0,9)) for i in range(length)])

def actions(conn, addr):
    t = 0
    #print(public_key)
    userk = conn.recv(2000)
    #userk = RSA.importKey(t)
    #print(userk)
    conn.send(public_key)
    userk = RSA.importKey(userk)
    msgrec = conn.recv(2000)
    msgrec = msgrec.decode("UTF-8")
    demsgrec = key.decrypt(ast.literal_eval(msgrec))
    demsgrec = demsgrec.decode(FORMAT)
    name,n1 = demsgrec.split(" ")
    n2 = generate_nonce()
    msgs = "supervisor " + n1 + " " + n2
    msgs = msgs.encode("UTF-8")
    msgs = str(userk.encrypt(msgs, 32))
    msgs = msgs.encode("UTF-8")
    conn.sendall(msgs)
    """order = conn.recv(2000)
    order = order.decode("UTF-8")
    scen,item = order.split(":")
    print(item)
    if item in items:
        x = 1"""
    data = conn.recv(1000)
    #print(data.decode("UTF-8"))
    data = data.decode("UTF-8")
    data = rempad(data)
    data = data.encode("UTF-8")
    keypaire = conn.recv(1000)
    keypairn = conn.recv(1000)
    keypaire = keypaire.decode("UTF-8")
    keypaire = rempad(keypaire)
    #rint(keypaire)
    keypaire = int(keypaire)
    keypairn = keypairn.decode("UTF-8")
    keypairn = rempad(keypairn)
    #print(keypairn)
    keypairn = int(keypairn)
    #print(data.decode("UTF-8"))
    #print(keypaire.decode("UTF-8"))
    #print(keypairn.decode("UTF-8"))
    signature = conn.recv(1000)
    signature = signature.decode("UTF-8")
    signature = rempad(signature)
    #print(signature)
    time,signature = signature.split('[{at}]')
   
            
    signature = int(signature)
    print(time)
    print(signature)
    hash = int.from_bytes(sha512(data).digest(), byteorder='big')
    hashFromSignature = pow(signature, keypaire, keypairn)
    print("Signature confirmed:", hash == hashFromSignature)
    order = conn.recv(2048) 
    order = order.decode("UTF-8")
    print(order)
    decrypted = key.decrypt(ast.literal_eval(order))
    order = decrypted.decode(FORMAT)
    print(order)
    for x in items:
        if x in order:
            t = t + 1
            break
        else:
            t = t + 0
    
    if t >= 1:
        verdict = "The purchase is"
        result = " possible, please wait for conformation with purchsing department."
    else:
        verdict = "The purchase is not"
        result = " possible, you will not be receiving a conformation from the purchasing department."
    msgf = verdict + result
    msgf = msgf.encode("UTF-8")
    encrypted = str(userk.encrypt(msgf, 32))
    encrypted = encrypted.encode("UTF-8")
    conn.send(encrypted)
    if t >= 1:
        purd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        purd.connect(ADDRP) 
        hashedm = int(hashlib.sha1(order.encode("utf-8")).hexdigest(), 16) % (10 ** 8)
        hashedm = str(hashedm)
        #print(hashedm)
        hashedmp = padding(hashedm)
        purd.sendall(hashedmp.encode("UTF-8"))
        keyPairep = padding(str(keyPair.e))
        purd.sendall((keyPairep.encode("UTF-8")))
        #print(keyPairep)
        #purd.sendall((keyPairep.encode("UTF-8")))
        #print(keyPair.e)
        keyPairnp = padding(str(keyPair.n))
        #print(keyPairnp)
        purd.sendall(((keyPairnp)).encode("UTF-8"))
        msg1 = hashedm
        msg1 = msg1.encode("UTF-8")
        hash = int.from_bytes(sha512(msg1).digest(), byteorder='big')
        signature2 = pow(hash, keyPair.d, keyPair.n)
        signature2 = str(signature2)
        #print(signature)
        signature2 = str(datetime.now()) + '[{at}]' + signature2
        signature2 = padding(signature2)
        signature2 = signature2.encode("UTF-8")
        #print(signature2)
        purd.sendall(signature2)
        print("Order now sent to purchasing department")
        
    else:
        print("Order will not be sent to purchasing department")
    conn.close()
    
    
      
    """
    scan,item = order.split(":")
    if item in items:
        conn.send(("YES YOU CAN BUY").encode("UTF-8"))
    else:
        conn.send(("NO YOU CANNOT BUY").encode("UTF-8"))
        """
    
    """
    if (hash == hashFromSignature):
        print("true")
        if item in items:
            conn.send(("YEAH BOI WE GOT IT").encode("UTF-8"))
        else:
            conn.send(("NO WE DONT GOT IT").encode("UTF-8"))
    else: 
        print("fake user")
    
    
    """
    
    
    
    
    
    """
    msg1 = conn.recv(2000)
    msg1 = msg1.decode("UTF-8")
    msg1 = userk.decrypt(ast.literal_eval(msg1))
    msg1 = msg1.decode("UTF-8")
    print(msg1)
    """
    
    """
    t = t.decode("UTF-8")
    sender,order,hashed = t.split("hash")
    if sender == "user":
        print()
        conn.send(("Order received from user").encode("UTF-8"))
    else:
        conn.send(("WHO TF U").encode("UTF-8"))
    """    
    
listener()
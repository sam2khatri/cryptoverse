# -*- coding: utf-8 -*-
"""
Created on Wed Feb 10 22:25:46 2021

@author: DELL
"""
import crypto
import genLargePrimes
from firebase import Firebase
import paho.mqtt.client as paho
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import serialization
import  base64


def setup():
       username = input("Enter a unique username : ")
       firebaseConfig = {
           "apiKey": "AIzaSyACbKcT-f79UePdd4HWlvH92tC5IRcRNzI",
           "authDomain": "encryption-chat-b0dd6.firebaseapp.com",
           "databaseURL": "https://encryption-chat-b0dd6-default-rtdb.firebaseio.com",
           "projectId": "encryption-chat-b0dd6",
           "storageBucket": "encryption-chat-b0dd6.appspot.com",
           "messagingSenderId": "500681488631",
           "appId": "1:500681488631:web:b8e0dc0fc8856a6a817bf2"
         }
       
       firebase = Firebase(firebaseConfig)
       db = firebase.database()
       
       users = db.get().each()
       users_list = [user.key() for user in users]
       
       
       

       client = paho.Client(username)
       #n, totient, private, public = crypto.runRSA(10)
       private,public = crypto.generateKeys()
       pem = public.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
       pem = pem.splitlines()[1:-1]
       print(pem)
       key=""
       for line in pem:
             key+= line.decode('utf-8')+'-'
       db.child(username).set(key)
       return username,client,private,public, db
       #return username, client, private, public, n, db

def on_connect(client, userdata, flags, rc):
       print("Connected with result code "+str(rc))
       return rc

def on_subscribe(client, userdata, mid, granted_qos):
       print("subscribed with code : "+str(mid))

def on_publish(client,userdata,result):             #create function for callback
       print("data published \n")
    

def on_disconnect(client, userdata, rc=0):
       print("DisConnected result code "+str(rc))
       client.loop_stop()

def on_message(client, userdata, message):
       msg = message.payload.decode('utf-8')
       #print(msg)
       #print(crypto.decrypt(msg, host.private, host.n))
       print(crypto.decrypt2(msg, host.private))
       #send_flag = input("\nDo you want to send message? [y/n] : ")
       
              

def _subscribe(host):
       host.client.connect("localhost",1883)
       host.client.on_connect = on_connect
       r = host.client.subscribe(host.username)
       print(r)

# =============================================================================
# def _publish(username, client, receiver, message, receiver_public_key, n):
#        client.publish(receiver, crypt.encrypt(username + " " + message, receiver_public_key, n))
# =============================================================================
       
def _publish(host,message):
       # ct_list = crypto.encrypt(message, host.receiver_public_key, int(host.n))
       ct_list = crypto.encrypt2(message, host.receiver_public_key)
       host.client.publish(host.receiver,ct_list)
       


class Host:
       def __init__(self,username,client, private, public):
              self.username = username
              self.client = client
              self.private = private
              self.public = public
       
       def get_receiver_username(self):
              receiver = input("Enter username of receiver : ")
              self.receiver=receiver
       
       def receiver_key(self,db):
              receiver_public_key = db.child(self.receiver).get().val()
               
              key = receiver_public_key.split('-')
              key = "\n".join(key)
              key = key.encode('utf-8')
              key = base64.b64decode(key)
              key = load_der_public_key(key, default_backend())
              
              #print(key)
              
              self.receiver_public_key = key      

#u ,c ,pr ,pub, n, db = setup()       
u, c, pr,  pub, db = setup()
host = Host(u,c,pr,pub)

host.get_receiver_username()
host.receiver_key(db)
#print(type(host.receiver_public_key))
print(host.__dict__)
#host.client.on_disconnect = on_disconnect
host.client.on_subscribe = on_subscribe
host.client.on_message = on_message
host.client.on_publish = on_publish
_subscribe(host)
time.sleep(1)
host.client.loop_start()

while True:
        msg = input("Enter your message : ")
        _publish(host,msg)
        
host.client.loop_stop()






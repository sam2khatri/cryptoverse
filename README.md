# cryptoverse

End to End encrypted chatting application which uses MQTT to send and receive messages. 

## Encryption

Encryption is done with help of RSA alogrithm which is based on public key encryption system. The algorithm generates a pair of keys namely public and private. 

Public key is used to encrypt messages and private key is used to decrypt. 

## Working

The public key of the user is stored on Firebase and anyone can use it to send encrypted messages to the user. The private key is stored on the system of the user itslef so no one except the user can decrypt messages. 

Everytime the user logs in, a new key pair is generated. (I will work on a better storage system).
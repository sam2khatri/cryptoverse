import random, os
import genLargePrimes
from random import randrange, getrandbits
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
import base64

def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    #print("\nPerforming Rabin Miller's Primality Test\n")
    for _ in range(k):
        a = randrange(2, n - 1)
        #print("Selecting a random number a : ", a)
        x = pow(a, r, n)
        #print("Calculating a=n(mod r) : ", x)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                #print("Calculating x=n(mod 2) : ", x)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def generate_prime_candidate(length):
    p = getrandbits(length)
    p |= (1 << length - 1) | 1
    return p


def generate_prime_number(length):
    p = 4
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
        #print("Generating a prime candidate : ", p)
    return p



def Extended_euclid(a, b):
	x0, x1, y0, y1 = 0, 1, 1, 0

	while a != 0:
		q, b, a = b//a, a, b%a
		y0, y1 = y1, y0 - q*y1
		x0, x1 = x1, x0 - q*x1

	return b, x0, y0


def generatePublicKey(totient):
	public_key = random.randrange(3, totient)
	while not is_prime(public_key):
		#print("Generating public key : ", public_key)
		public_key += 1
	return public_key


def generatePrivateKey(public_key, totient):
	g, _, private_key = Extended_euclid(int(totient), int(public_key))
	if private_key > totient:
		private_key = private_key % totient
	elif private_key < 0:
		private_key += totient
	return private_key

def runRSA(message, bits):
	p = generate_prime_number(bits)
	q = generate_prime_number(bits)
	n = p*q
	totient = (p-1)*(q-1)
	public_key = generatePublicKey(totient)
	private_key = generatePrivateKey(public_key, totient)
	print("Public key: ", public_key)
	print("Private key: ", private_key)
	enc_list = []
	decrypted_mess = ""

	for char in message:
		mess = ord(char)
		enc_mess = str(pow(mess, public_key, n))
		enc_list.append(enc_mess)

	print("Cipher Text : ", enc_mess)

	for enc_mess in enc_list:
		decr = (pow(int(enc_mess), private_key, n))
		decrypted_mess += chr(decr)

	print("Decrypted Text: ", decrypted_mess)

def runRSA(bits):
	p = generate_prime_number(bits)
	q = generate_prime_number(bits)
	n = p*q
	totient = (p-1)*(q-1)
	public_key = generatePublicKey(totient)
	private_key = generatePrivateKey(public_key, totient)
	#print("Prime numbers are\np : ", p, "\nq : ", q)
	#print("Modulus : ", n)
	#print("Euler's Totient : ", totient)
	#print("Public key: ", public_key)
	#print("Private key: ", private_key)
	return n, totient, private_key, public_key


def encrypt(message, public_key, n):
	enc = ""
	#print("\nEncrypting your message\n")
	for char in message:
		mess = ord(char)
		enc_mess = str(pow(mess, public_key, n))
		#print(enc_mess)
		enc+= enc_mess + " "
	return enc

def decrypt(ct_list, private_key, n):
    decrypted_mess = " "
    #print(type(ct_list))
    ct_list = ct_list.split()
	#print("\nDecrypting your message\n")
    for ct in ct_list:
        decr = (pow(int(ct), private_key, n))
		#print(decr)
        decrypted_mess += chr(decr)

    return decrypted_mess

def generateKeys():
       private_key = rsa.generate_private_key(public_exponent=65537,
                                              key_size=2048,
                                              backend=default_backend())
       public_key = private_key.public_key()
       pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
       pem = pem.splitlines()[1:-1]
       #print(pem)
       key=""
       for line in pem:
             key+= line.decode('utf-8')+'-'
       #print(key)

       key = key.split('-')
       key = '\n'.join(key)
       key = key.encode('utf-8')
       #print(key)
       key = base64.b64decode(key)
       key = load_der_public_key(key,default_backend())
       #print(key)
       
       return private_key,public_key
#message = "hello"

def encrypt2(message,public_key):
       message_bytes = bytes(message, encoding='utf8') 
       ciphertext = public_key.encrypt(message_bytes,padding.OAEP(
              mgf=padding.MGF1(algorithm=hashes.SHA1()),
              algorithm=hashes.SHA1(),
              label=None
              ))

       ciphertext  = str(base64.b64encode(ciphertext), encoding='utf-8')
       #print(ciphertext)
       return ciphertext
       
def decrypt2(ciphertext,private_key):
       ciphertext_decoded = base64.b64decode(ciphertext) if not isinstance(ciphertext, bytes) else ciphertext

       plain_text = private_key.decrypt(ciphertext_decoded,padding.OAEP(
              mgf=padding.MGF1(algorithm=hashes.SHA1()),
              algorithm=hashes.SHA1(),
              label=None
              ))
       plain_text = str(plain_text, encoding='utf8')
       #print(plain_text)
       return plain_text

#x, y = generateKeys()
# =============================================================================
# #bits = int(input("Enter bits: "))
# n, totient, private_key, public_key = runRSA(10)
# #message = input("Enter message: ")
# message =  "hello"
# ct_list = encrypt(message, public_key, n)
# print("Cipher Text: ", ct_list)
# pt = decrypt(ct_list, private_key, n)
# print("Plain Text: ", pt)
# 
# =============================================================================

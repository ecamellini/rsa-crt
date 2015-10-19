#!/usr/bin/python2.7
import sys
import aes
import rsa
import time
from contextlib import contextmanager


@contextmanager
def measure_time(label):
    t1 = time.time()
    yield
    t2 = time.time()
    print 'TIMING: %s: %0.6f ms' % (label, (t2-t1)*1000)


if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print "Input missing. Program terminated."
        print "Usage: ./aes-rsa-crt.py 'input message'"
        sys.exit(0)
    else:

        ### BOB ###
        print "___BOB___"
        # Bob generates its RSA key pair"
        print "BOB generates an RSA key pair:"
        rsa_bob = rsa.RSACipher()
        with measure_time('RSA key pair generation'):
            rsa_bob.gen_key_pair(1024)
        public_key_bob = rsa_bob.get_public_key()
        print "Bob's public key: ", public_key_bob
        print

        ### ALICE ###
        print "___ALICE___"
        # ALICE has an AES secret key, she encrypts it with Bob's public
        # key and she sends it to Bob. She sends also and AES encrypted
        # message

        ### AES-128 initialization, Alice has the key ###
        key = "HardcodedKey?lol"  # 128-bits key
        aes128 = aes.AESCipher(key)

        input = sys.argv[1]  # reading and printing the message
        print "Alice's message (input): ", input

        ### Step 1 - AES-128 encryption ###
        with measure_time('AES-128 encryption'):
            ciphertext = aes128.encrypt(input)
        print "AES-128 ciphertext: ", ciphertext

        ### Step 2 - RSA Key encryption
        rsa_alice = rsa.RSACipher()
        rsa_alice.set_public_key(public_key_bob)
        with measure_time('RSA encryption'):
            e_key = rsa_alice.encrypt_string(key)
        print "Encrypted AES key: ", e_key
        print

        ### BOB ###
        print "___BOB___"
        # BOB receives the encrypted AES key, he decrypts it using
        # its private RSA key and then he uses it to decrypt the
        # secret message

        ### Step 3.1 - Bob receives and decrypt the secret key ###
        with measure_time('RSA decription (no crt)'):
            key = rsa_bob.decrypt_string(e_key)
        #print "Key: ", key

        ### step 3.2 - The same as 3.1, but with CRT optimization ###
        with measure_time('RSA decryption (crt)'):
            key = rsa_bob.decrypt_string(e_key, True)
        #print "Key (CRT): ", key

        ### Step 4 - AES-128 decryption ###
        with measure_time('AES decryption'):
            plaintext = aes128.decrypt(ciphertext)
        print "Received plaintext: ", plaintext

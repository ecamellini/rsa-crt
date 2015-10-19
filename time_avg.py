#!/usr/bin/python2.7
import sys
import aes
import rsa
import time
from contextlib import contextmanager

ITERATIONS = 1000


@contextmanager
def measure_time(times_list):
    t1 = time.time()
    yield
    t2 = time.time()
    times_list.append((t2-t1)*1000)


def list_avg(l):
    return sum(l)/len(l)

if __name__ == "__main__":

    if(len(sys.argv) != 2):
        print "Input missing. Program terminated."
        print "Usage: ./aes-rsa-crt.py 'input message'"
        sys.exit(0)
    else:
        key_times = []
        aes_enc_times = []
        rsa_enc_times = []
        rsa_crt_dec_times = []
        rsa_dec_times = []
        aes_dec_times = []

        for i in range(ITERATIONS):
            print "Execution %d..." % i
            rsa_bob = rsa.RSACipher()
            with measure_time(key_times):
                rsa_bob.gen_key_pair(1024)
            public_key_bob = rsa_bob.get_public_key()
            key = "HardcodedKey?lol"  # 128-bits key
            aes128 = aes.AESCipher(key)

            input = sys.argv[1]  # reading and printing the message
            with measure_time(aes_enc_times):
                ciphertext = aes128.encrypt(input)

            rsa_alice = rsa.RSACipher()
            rsa_alice.set_public_key(public_key_bob)
            with measure_time(rsa_enc_times):
                e_key = rsa_alice.encrypt_string(key)

            with measure_time(rsa_dec_times):
                key = rsa_bob.decrypt_string(e_key)

            with measure_time(rsa_crt_dec_times):
                key = rsa_bob.decrypt_string(e_key, True)

            with measure_time(aes_dec_times):
                plaintext = aes128.decrypt(ciphertext)

        print "Final plaintext: ", plaintext
        print "AVG times over %d executions:" % ITERATIONS
        print "KEY generation time: %0.6f ms" % list_avg(key_times)
        print "AES encryption time: %0.6f ms" % list_avg(aes_enc_times)
        print "RSA encryption time: %0.6f ms" % list_avg(rsa_enc_times)
        print "RSA decryption time: %0.6f ms" % list_avg(rsa_dec_times)
        print "RSA + CRT dec. time: %0.6f ms" % list_avg(rsa_crt_dec_times)
        print "AES decryption time: %0.6f ms" % list_avg(aes_dec_times)

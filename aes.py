import base64
from Crypto.Cipher import AES
from Crypto import Random


#stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
#stackoverflow.com/questions/12562021/aes-decryption-padding-with-pkcs5-python
BS = AES.block_size
_pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
_unpad = lambda s: s[:-ord(s[len(s)-1:])]


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = _pad(raw)
        iv = Random.new().read(BS)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return _unpad(cipher.decrypt(enc[16:]))


### test-main ###
import sys

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print "Input missing. Program terminated."
        print "Usage: ./aes-rsa-crt.py 'input message'"
        sys.exit(0)
    else:
        input = sys.argv[1]
        print "User input: ", input

        key = "Not-a-random-key"
        aes128 = AESCipher(key)
        ciphertext = aes128.encrypt(input)
        print ciphertext
        plaintext = aes128.decrypt(ciphertext)
        print plaintext

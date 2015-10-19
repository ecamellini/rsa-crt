import base64
from Crypto.Util import number


class RSACipher:

    def __init__(self):
        self.e = None
        self.d = None
        self.n = None
        None

    def set_public_key(self, (e, n)):
        self.e = e
        self.n = n
        self.block_size = len(str(n))

    def _gen_primes(self, bit_length):
        self.p = number.getStrongPrime(bit_length)
        self.q = number.getStrongPrime(bit_length)

    def gen_key_pair(self, bit_length):
        if(bit_length % 2 != 0):
            raise ValueError("Bit length must be a multiple of 2")

        if(bit_length < 8):
            raise ValueError("Bit length must be at least 8 bits")

        bits_pq = bit_length/2

        self.n = 0
        while (self.n.bit_length() != bit_length):
            self._gen_primes(bits_pq)
            self.n = self.p*self.q

        self.phi_n = (self.p-1)*(self.q-1)

        self.e = 0
        while((self.e <= 3) |
              (self.e >= self.phi_n) |
              (number.GCD(self.e, self.phi_n) != 1)):
            self.e = number.getRandomInteger(self.phi_n.bit_length())

        self.d = number.inverse(self.e, self.phi_n)
        self.block_size = len(str(self.n))

        #Initializing the CRT values
        self._init_crt()

    def _init_crt(self):
        self.dp = self.d % (self.p - 1)
        self.dq = self.d % (self.q - 1)
        self.q_inv = number.inverse(self.q, self.p)

    def get_public_key(self):
        if (self.e is None) | (self.n is None):
            raise UnboundLocalError("Key pair not generated.")
        return (self.e, self.n)

    def encrypt(self, m):
        if (self.e is None) | (self.n is None):
            raise UnboundLocalError("Encryption public key not set.")
        return pow(m, self.e, self.n)

#crypto.stackexchange.com/questions/2575/chinese-remainder-theorem-and-rsa
#en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
    def decrypt(self, c, crt=False):
        if (self.d is None) | (self.n is None):
            raise UnboundLocalError("Key pair not generated.")
        if crt is True:
            m1 = pow(c, self.dp, self.p)
            m2 = pow(c, self.dq, self.q)
            h = (self.q_inv * (m1 - m2)) % self.p
            return m2 + h*self.q
        else:
            return pow(c, self.d, self.n)

    def encrypt_string(self, s):
        ciphertext = ""
        for c in s:
            e_c = str(self.encrypt(ord(c)))
            while len(e_c) < self.block_size:
                e_c = '0' + e_c
            ciphertext += e_c
        return base64.b64encode(ciphertext)

    def decrypt_string(self, s, crt=False):
        s = base64.b64decode(s)
        plaintext = ""
        block = ""
        for c in s:
            if(len(block) < self.block_size):
                block += c
            else:
                plaintext += chr(self.decrypt(int(block)))
                block = c
        plaintext += chr(self.decrypt(int(block), crt))
        return plaintext


### Test main ###
if __name__ == "__main__":

    #NUMERIC EXAMPLE
    # m = 5000  # Must be < n
    # print "Msg: ", m
    # rsa = RSACipher()
    # rsa.gen_key_pair(1024)
    # print "Public key: ", rsa.get_public_key()
    # c = rsa.encrypt(m)
    # print "Ciphertext: ", c
    # print "Plaintext: ", rsa.decrypt(c, True)

    #STRING EXAMPLE
    m = "Asdasd"
    print "Msg: ", m
    rsa = RSACipher()
    rsa.gen_key_pair(1024)
    print "Public key: ", rsa.get_public_key()
    c = rsa.encrypt_string(m)
    print "Ciphertext: ", c
    print "Plaintext: ", rsa.decrypt_string(c, True)

from random import randrange

def gcd(x, y):
    if (x == 0 or y == 0): return 1
    while (y != 0): x, y = y, x % y
    return x

def coprime(a):
    c = randrange(1, a)
    while gcd(c, a) != 1: c = randrange(1, a)
    return c

def mod_inverse(a, n):
    # from https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    t, newt = 0, 1
    r, newr = n, a
    while (newr != 0):
        quotient = r // newr
        t, newt = newt, t - quotient*newt
        r, newr = newr, r - quotient*newr
    if (r > 1): raise Exception('a is not invertible')
    if (t < 0): t += n
    return t

def find_power_mod(a, b, m):
    # exponentially reduced execution time compared to (a**b)%m for large numbers
    d = 1
    while (b > 0):
        if (b%2 == 1): d = (d*a) % m
        a, b = a**2 % m, b // 2
    return d

class RSACryptosystem:
    def __init__(self, e=None, n=None):
        # use this object only for encryption from client
        if (e and n):
            self.e = e
            self.n = n
            return
        # p and q are large primes with >=150 digits
        # predefined numbers from https://primes.utm.edu/lists/small/small2.html#150
        self.p = 204616454475328391399619135615615385636808455963116802820729927402260635621645177248364272093977747839601125961863785073671961509749189348777945177811
        self.q = 583131835487211382864869404486578252043523081801125909471858006868782832566750509413463775974331289075956651335069566640737433078846977125660198697601
        # n = p * q
        self.n = self.p * self.q
        # T = (p-1) * (q-1)
        self.T = (self.p-1) * (self.q-1)
        # e is coprime to T
        self.e = coprime(self.T)
        # self.e = 65537
        # d is the modular inverse of e (mod T)
        self.d = mod_inverse(self.e, self.T)

    def encrypt(self, message):
        emsg = []
        epart = 0
        for i, c in enumerate(message):
            # concatenate Unicode characters
            epart = (epart<<16) + ord(c)
            # encrypt the large number which is a concatenation of
            # every n=32 characters.
            # the value of n depends on the size of the primes p and q
            # if n value is too small, the encrypted message becomes
            # too big in relation to the original message.
            # if n is too big, the encrypted message cannot be 
            # successfully decrypted.
            if ((i+1)%32 == 0):
                emsg.append(find_power_mod(epart, self.e, self.n))
                epart = 0
        # encrypt the last part of message in cases where 
        # len(message) mod n != 0
        if (epart != 0):
            emsg.append(find_power_mod(epart, self.e, self.n))
        return emsg

    def decrypt(self, message):
        if (hasattr(self, 'd') == False):
            raise Exception('This RSACryptosystem object cannot be used for decryption.')
        dmsg = []
        # decrypt part by part
        for epart in message:
            dpart = find_power_mod(epart, self.d, self.n)
            # find the number of Unicode characters encoded in the large decrypted number
            n = int(len(hex(dpart)[2:])/4)
            # decode all characters present in the large decrypted number
            for i in range(n, -1, -1):
                # extract the left most Unicode character
                dc = dpart>>(i*16)
                # decode Unicode character and add to decrypted message
                dmsg.append(chr(dc))
                # remove decoded character
                dpart -= dc<<(i*16)
        return ''.join(dmsg)

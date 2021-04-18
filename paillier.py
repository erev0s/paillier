import math
import random
from random import shuffle
import sys
import gmpy2
from time import time
from Crypto.Util.number import getPrime


# In[2]:


def gcd(a,b):
    while b > 0:
        a, b = b, a % b
    return a
    
def lcm(a, b):
    return a * b // gcd(a, b)    
    
    
def int_time():
    return int(round(time() * 1000))

class PrivateKey(object):
    def __init__(self, p, q, n):
        #self.l = lcm(p-1,q-1)----This is added as requested by the setup BUT not used, shortcut is used!
        self.l = (p-1) * (q-1)
        #self.m = gmpy2.invert(gmpy2.f_div(gmpy2.sub(gmpy2.powmod(n+1,self.l,n*n),gmpy2.mpz(1)),pub.n),n) --- Shortcut used instead of it
        self.m = gmpy2.invert(self.l, n)  #1/fi(n)
    def __repr__(self):
        return '<PrivateKey: %s %s>' % (self.l, self.m)

class PublicKey(object):

    @classmethod
    def from_n(cls, n):
        return cls(n)
    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1
    def __repr__(self):
        return '<PublicKey: %s>' % self.n
    
def generate_keypair(bits):
    p_equal_q = True
    while p_equal_q:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if (p!=q):
            p_equal_q = False
    n = p * q
    return PrivateKey(p, q, n), PublicKey(n)

def encrypt(pub, plain):
    one = gmpy2.mpz(1)
    state = gmpy2.random_state(int_time())
    r = gmpy2.mpz_random(state,pub.n)
    while gmpy2.gcd(r,pub.n) != one:
        state = gmpy2.random_state(int_time())
        r = gmpy2.mpz_random(state,pub.n)
    x = gmpy2.powmod(r,pub.n,pub.n_sq)
    cipher = gmpy2.f_mod(gmpy2.mul(gmpy2.powmod(pub.g,plain,pub.n_sq),x),pub.n_sq)
    return cipher

def decrypt(priv, pub, cipher):
    one = gmpy2.mpz(1)
    x = gmpy2.sub(gmpy2.powmod(cipher,priv.l,pub.n_sq),one)
    plain = gmpy2.f_mod(gmpy2.mul(gmpy2.f_div(x,pub.n),priv.m),pub.n)
    if plain >= gmpy2.f_div(pub.n,2):
        plain = plain - pub.n
    return plain

def addemup(pub, a, b):
    return gmpy2.mul(a,b)

def multime(pub, a, n):
    return gmpy2.powmod(a, n, pub.n_sq)


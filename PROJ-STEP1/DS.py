import math
import os
import random
import string
import warnings
import pyprimes
from Crypto.Hash import SHA3_256
from Crypto.Util import number

def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b//a, b % a
        m, n = x-u*q, y-v*q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

# returns "p" s.t. q|p-1
def getLargeDLprime(q, bitsize):
    while True:
        k = number.getRandomNBitInteger(bitsize)
        # using q here because q|p-1, where p must be also prime
        p = q * k + 1
        if number.isPrime(p):
            return p

# Creates random string of ASCII character of length "size"
def random_string(size):
    return (''.join(random.choices( \
            string.ascii_uppercase + string.ascii_lowercase + string.digits \
            , k=size)))

# primes qsize-bit q, psize-bit p where q|p-1
# and g is primitive element i.e. g^q = 1 mod p 
# and g can generate subgroup of Zp* with q elements
def GenerateParams(qsize, psize):
    q = number.getPrime(qsize)
    p = getLargeDLprime(q, psize - qsize) 

    tmp = (p-1)//q
    g = 1
    while g == 1:
        alpha = random.randrange(1, p)
        g = pow(alpha, tmp, p)

    return q, p, g

def GenerateOrRead(file):
    # Does file exist
    if os.path.isfile(file):
        f = open(file, "r")
        q = int(f.readline())
        p = int(f.readline())
        g = int(f.readline())
        f.close()
    else: # File doesn't exist, create params by yourself 
        q, p, g = GenerateParams(224, 2048)

        # write to file
        f = open(file,"w")
        f.write(str(q)+"\n")
        f.write(str(p)+"\n")
        f.write(str(g))
        f.close()

    return q, p, g

# computes alpha and beta s.t.
# beta = g^alpha mod p
# where alpha is secret, and beta is public key
def KeyGen(q, p, g):
    alpha = random.randint(1,q)
    beta = pow(g , alpha, p)
    return alpha, beta

# signs message with given produre in the assignment
def SignGen(message, q, p, g, alpha):
    message = message.decode("utf-8")
    h = SHA3_256.new(bytes(str(message), 'utf-8'))
    h = int(h.hexdigest(), 16)

    k = random.randint(1, q - 2)
    r = pow(g,k,p) % q
    s = (alpha * r) - (k * h)
    return s, r

# verifies message with given produre in the assignment
def SignVer(message, s, r, q, p, g, beta):
    message = message.decode("utf-8")
    h = SHA3_256.new(bytes(str(message), 'utf-8'))
    h = int(h.hexdigest(), 16)

    v = modinv(h, q)
    z1 = (s * v) % q
    z2 = (r * v) % q

    # For calculate -z1 power of g in mod p
    # g^-z1 is equal to g^-z1+q in mod p
    # because g^q = 1 mod p
    z1 = -z1 + q

    u1 = pow(g,z1,p)
    u2 = pow(beta, z2, p)
    u = ((u1 * u2) % p) % q

    if u == r:
        # Signature Accepted
        # print("Accepted")
        return 0
    else: 
        # Signature Rejected
        # print("Rejected")
        return 1

import random
import sys
from ecpy.curves import Curve,Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from ecpy.formatters import decode_sig, encode_sig

from Crypto.Hash import SHA3_256
from Crypto.Util import number as crypt

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

# generate signature
def SignGen(message, E, sA):
    sk = ECPrivateKey(sA, E)
    G = E.generator
    signer = ECDSA()
    sig = signer.sign(message, sk)
    (r, s) = decode_sig(sig)
    return s, r

# verifies signature
def SignVer(message, s, r, E, QA):
    verifier = ECDSA()
    pk = ECPublicKey(QA)
    sig = encode_sig(r, s)
    try:
        assert(verifier.verify(message,sig, pk))
        return 0
    except:
        return 1

# generate a secret/public key pair
def KeyGen(E):
    # number of EC points on the curve
    order = E.order
    # G is going to be used for scalar multiplication on the curve
    G = E.generator
    # private key
    sA = random.randint(0,order)
    # public key(EC point)
    QA = sA*G
    return sA, QA

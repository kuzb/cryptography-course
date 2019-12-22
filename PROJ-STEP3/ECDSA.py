import random
from Crypto.Hash import SHA3_256

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

def getDigest(message):
    return (SHA3_256.new(message)).digest()

def getHexdigest(message):
    return (SHA3_256.new(message)).hexdigest()

# generate signature
def SignGen(message, E, sA):
    # number of EC points on the curve
    order = E.order
    # G is going to be used for scalar multiplication on the curve
    G = E.generator

    h = int.from_bytes( getDigest(message), byteorder='big') % order

    k = random.randint(1, order-1) 

    R = (k*G)  
    # random point on the curve
    r = ((R.x) % order)
    # signature proof
    s = (r*sA - h*k) % order
    return s, r

# verifies signature
def SignVer(message, s, r, E, QA):
    # number of EC points on the curve
    order = E.order
    # G is going to be used for scalar multiplication on the curve
    G = E.generator

    h = int.from_bytes( getDigest(message), byteorder='big') % order

    invH = modinv(h, order) % order
    z1 = (s*invH) % order
    z2 = (r*invH) % order

    # recover the random point used during the signing
    R = (order-z1)*G + z2*QA
    R = R.x % order

    return 0 if r == R else -1

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

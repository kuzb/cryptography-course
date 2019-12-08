import math


def phi(n):
    amount = 0
    for k in range(1, n + 1):
        if math.gcd(n, k) == 1:
            amount += 1
    return amount


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

# shifts letters by choosen amount


def shift(letter, amount):
        # ASCII for A-Z is between 65-90
    if ord(letter) >= 65 and ord(letter) <= 90:
        char = ord(letter)-65
        letter = chr((char + amount) % 26 + 65)
    return letter

# shifts whole strings by choosen amount


def shiftCombinations(string):
    for i in range(1, 26):
        shifted = ''.join(shift(ch, i) for ch in string)
        return shifted

# Returns tuples with Uppercase letter only, otherwise return 0


def ignoreNonUppercase(tuplee):
    return 0 if ord(tuplee[0]) > 90 and ord(tuplee[0]) < 90 else tuplee[1]


def mostFrequentLetter(string):
    # Creates a list of tuples s.t. (letter, frequency), then find the
    # tuple where frequency is the highest(while ignoreing space)
    # , then returns only the letter in tuple
    return max(list((letter, string.count(letter)) for letter in string), key=ignoreNonUppercase)[0]

# option to encrypt only ASCII uppercase


def encryptCharAffine(plaintext, a, b, n, onlyUppercase):
    if onlyUppercase:
        # used for alphabets 1-25
        return plaintext if ord(plaintext) > 90 and ord(plaintext) < 90 \
            else chr(((a * (ord(plaintext) - 65) + b) % n) + 65)

    return chr((a * ord(plaintext) + b) % n)

# option to decrypt only ASCII uppercase


def decryptCharAffine(ciphertext, a, b, n, onlyUppercase):
    if onlyUppercase:
        # used for alphabets 1-25
        return ciphertext if ord(ciphertext) > 90 and ord(ciphertext) < 90 \
            else chr(((a * ((ord(ciphertext) - 65) - b)) % n) + 65)

    return chr((a * (ord(ciphertext) - b)) % n)

# modified for ASCII uppercase


def encrypt(plaintext, key):
    keyLength = len(key)
    keyNumList = [ord(i) for i in key]
    plaintextNumList = [ord(i) for i in plaintext]
    ciphertext = ''
    for i in range(len(plaintextNumList)):
        value = (plaintextNumList[i] + keyNumList[i % keyLength]) % 26
        ciphertext += chr(value + 65)
    return ciphertext

# modified for ASCII uppercase


def decrypt(ciphertext, key):
    keyLength = len(key)
    keyNumList = [ord(i) for i in key]
    ciphertextNumList = [ord(i) for i in ciphertext]
    plaintext = ''
    for i in range(len(ciphertextNumList)):
        value = (ciphertextNumList[i] - keyNumList[i % keyLength]) % 26
        plaintext += chr(value + 65)
    return plaintext


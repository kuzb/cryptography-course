import os
import random
from Crypto.Hash import SHA3_256
from MerkleTree import MerkleTree
from DS import SignGen, KeyGen

import hashlib

def getHash(message):
    return hashlib.sha3_256(message.encode("utf-8")).hexdigest()
    # h = SHA3_256.new(bytes(str(message), 'utf-8'))
    # return str(h.hexdigest())



def PoWPre(q, p, g, TxCnt, filename):
    if os.path.isfile(filename):
        f = open(filename, "r")
        file = f.readlines()
        f.close()

        # each transaction is 7 lines
        TxLen = 7
        # list of transactions
        transactions = [''.join(file[n:n+7])
                        for n in range(0, TxLen*TxCnt, TxLen)]

        merkle = MerkleTree(transactions, getHash)
        root = merkle.build()

        return root


def PoW(PoWLen, q, p, g, TxCnt, filename):
    root = PoWPre(q, p, g, TxCnt, filename)

    nonce = ""
    powValue = ""
    while powValue == "" or powValue[:PoWLen] != PoWLen*"0":
        nonce = str(random.getrandbits(128))
        powValue = getHash(str(root) + str(nonce))

    if os.path.isfile(filename):
        f = open(filename, "r")
        file = f.readlines()
        f.close()

    text = ''.join([element for element in file])
    text += "Nonce: " + nonce + "\n"

    return text


def CheckPow(p, q, g, PoWLen, TxCnt, filename):
    root = PoWPre(q, p, g, TxCnt, filename)
    if os.path.isfile(filename):
        f = open(filename, "r")
        file = f.readlines()
        f.close()

        # Getting nonce from the lastline
        lastLine = file[-1]
        num = int(''.join(filter(str.isdigit, lastLine)))
        nonce = str(num)

        powValue = getHash(str(root) + str(nonce))

        if powValue == "" or powValue[:PoWLen] != "0"*PoWLen:
            return ""
        else:
            return powValue

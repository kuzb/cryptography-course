import os
import random
from Crypto.Hash import SHA3_256
from MerkleTree import MerkleTree
from DS import SignGen, KeyGen
from multiprocessing import Pool
from hashlib import sha256
from time import time

def getHash(message):
    return SHA3_256.new(bytes(str(message), 'utf-8')).hexdigest()
    # return hashlib.sha3_256(message).hexdigest()
#     # h = SHA3_256.new(bytes(str(message), 'utf-8'))
#     # return str(h.hexdigest())


# def PoWPre(q, p, g, TxCnt, filename):
#     TxLen = 7

#     file = open(filename, "r")
#     lines = file.readlines()
#     file.close()

#     hashTree = []
#     for i in range(0,TxCnt):
#         transaction = "".join(lines[i*TxLen:(i+1)*TxLen])
#         hashTree.append(getHash(transaction))

#     t = TxCnt
#     j = 0
#     while (t>1):
#         for i in range(j,j+t,2):
#             hashTree.append(getHash(hashTree[i]+hashTree[i+1]))
#         j += t
#         t = t>>1

#     root_hash = hashTree[2*TxCnt-2]
   
#     return root_hash

def PoWPre(q, p, g, TxCnt, filename):
    if os.path.isfile(filename):
        f = open(filename, "r")
        file = f.readlines()
        f.close()

        # each transaction is 7 lines
        TxLen = 7
        # list of transactions
        transactions = [''.join(file[n:n+TxLen])
                        for n in range(0, TxLen*TxCnt, TxLen)]

        # transactions = [t.replace('\n','') for t in transactions]
        # transactions = [t.strip('\n') for t in transactions]
        # transactions = [t.encode("UTF-8") for t in transactions]

        # print(transactions[0])

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

    text = ''.join(file[::])
    text += "Nonce: " + nonce + "\n"

    return text

# def PoW(PoWLen, q, p, g, TxCnt, filename):
#     root = PoWPre(q, p, g, TxCnt, filename)

#     nonce = ""
#     powValue = ""
#     while powValue == "" or powValue[:PoWLen] != PoWLen*"0":
#         nonce = str(random.getrandbits(128))
#         powValue = getHash(str(root) + str(nonce))

#     if os.path.isfile(filename):
#         f = open(filename, "r")
#         file = f.readlines()
#         f.close()

#     text = ''.join(file[::])
#     text += "Nonce: " + nonce + "\n"

#     return text


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

        print(nonce)
        powValue = getHash(str(root) + nonce )

        if powValue == "" or powValue[:PoWLen] != "0"*PoWLen:
            print(powValue)
            return ""
        else:
            return powValue

# def CheckPow(p, q, g, PoWLen, TxCnt, filename):
#     root = PoWPre(q, p, g, TxCnt, filename)

#     if os.path.isfile(filename):
#         f = open(filename, "r")
#         file = f.readlines()
#         f.close()

#         # Getting nonce from the lastline
#         lastLine = file[-1]
#         num = int(''.join(filter(str.isdigit, lastLine)))
#         nonce = str(num)

#         powValue = getHash(str(root) + str(nonce))

#         if powValue == "" or powValue[:PoWLen] != "0"*PoWLen:
#             return ""
#         else:
#             return powValue


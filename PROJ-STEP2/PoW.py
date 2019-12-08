import random
import os
from multiprocessing import Pool
from time import time
from Crypto.Hash import SHA3_256
from MerkleTree import MerkleTree
from DS import SignGen, KeyGen


def getHash(message):
    return (SHA3_256.new(bytes(str(message), "UTF-8"))).hexdigest()

# Checks for suitable nonce in range of nonceRange
def _PoW(args):
    PowLen, root, nonceRange = args

    powValue = ""
    for nonce in range(nonceRange[0], nonceRange[1]):
        powValue = getHash(root + str(nonce))
        if powValue != "" and powValue[:PowLen] == PowLen*"0":
            # found suitable nonce in range
            return nonce

    # couldn't find suitable nonce
    return None

def PoW(PoWLen, q, p, g, TxCnt, filename):
    # hash root of merkle tree for given transaction in "filename"
    root = PoWPre(q, p, g, TxCnt, filename)

    # number of processes
    processes = 6
    # size of input each process will move over
    batchSize = 2**20
    pool = Pool(processes)

    # Nonce begins from smalles 120 bit integer
    nonce = int('1'+ 119*"0",2)

    solutions = []
    while True:
        nonceRanges = [
            (nonce + i * batchSize,
             nonce + (i+1) * batchSize)
            for i in range(processes)
        ]

        params = [
            (PoWLen, root, nonceRange) for nonceRange in nonceRanges
        ]

        solutions = pool.map(_PoW, params)

        # filter out non None solutions
        solutions = list( filter(None, solutions) )

        # if real solutions exist, we are done!
        if len(solutions) > 0:
            break

        # couldn't find a solution, so increment nonce for next round
        nonce += processes * batchSize


    # Get one of the solutions
    nonce = solutions.pop()

    if os.path.isfile(filename):
        f = open(filename, "r")
        file = f.readlines()
        f.close()

    text = ''.join(file[::])
    text += "Nonce: " + str(nonce) 

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

        powValue = getHash(str(root) + nonce)

        if powValue == "" or powValue[:PoWLen] != "0"*PoWLen:
            # nonce is not suitable for our requirments
            return ""
        else:
            return powValue


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

        merkle = MerkleTree(transactions, getHash)
        # root is merkle tree root
        root = merkle.build()

        return root

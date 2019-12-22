import os
import random
from multiprocessing import Pool
from time import time 
import string
import math
from Crypto.Hash import SHA3_256
from MerkleTree import MerkleTree

def getDigest(message):
    return (SHA3_256.new(message)).digest()

def getHexdigest(message):
    return (SHA3_256.new(message)).hexdigest()

def AddBlock2Chain(PoWLen, TxCount, block_candidate, PrevBlock):
    if len(PrevBlock) == 0:
        PrevPoW = '00000000000000000000'   
    else:
        H_r = getRoot(TxCount, PrevBlock, 9) #get Hash root 
        
        PrevPoW = PrevBlock[-2][14:-1]
        nonce = int(PrevBlock[-1][7:-1])
        PrevPoW = PrevPoW.encode('UTF-8') #cast to bytes
        digest = H_r + PrevPoW + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder = 'big')
        PrevPoW = SHA3_256.new(digest).hexdigest()
    
    HR = getRoot(TxCount, block_candidate, 9) 
    
    #Result Block
    responseBlock = "".join(block_candidate) 
    responseBlock += "Previous PoW: " + str(PrevPoW)
    responseBlock += "\n"
    
    nonce = getNonce(HR, PrevPoW, PoWLen) #Perfect nonce
    
    responseBlock += "Nonce: " + str(nonce) #Add to block
    responseBlock += " \n"
    return (str(responseBlock)), PrevPoW   

def getRoot(TxCnt, Block, TxLen):
    # list of transactions
    transactions = ["".join(Block[n:n+TxLen])
                    for n in range(0, TxLen*TxCnt, TxLen)]

    merkle = MerkleTree(transactions, getDigest)
    # root is merkle tree root
    root = merkle.build()

    return root

def _getNonce(args):
    PowLen, root, PrevPoW, nonceRange = args

    powValue = ""
    for nonce in range(nonceRange[0], nonceRange[1]):
        powValue = getHexdigest( root +  bytes(PrevPoW ,'UTF-8') + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder = 'big'))
        if powValue != "" and powValue[:PowLen] == PowLen*"0":
            # found suitable nonce in range
            return nonce

    # couldn't find suitable nonce
    return None


def getNonce(root, PrevPoW, PoWLen):
    # number of processes
    processes = 6
    # size of input each process will move over
    batchSize = 2**10
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
            (PoWLen, root, PrevPoW, nonceRange) for nonceRange in nonceRanges
        ]

        solutions = pool.map(_getNonce, params)

        # filter out non None solutions
        solutions = list( filter(None, solutions) )

        # if real solutions exist, we are done!
        if len(solutions) > 0:
            break

        # couldn't find a solution, so increment nonce for next round
        nonce += processes * batchSize


    # Get one of the solutions
    nonce = solutions.pop()

    return nonce
    

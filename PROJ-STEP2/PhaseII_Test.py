#########################################
##  Do not change this file            ##
## Your codes must work with this file ##
#########################################

import math
import random
import string
import warnings
import sympy
import DS       # This is the file from Phase I
import Tx       # This is the first file you have to submit in the second phase 
import PoW      # This is the second file you have to submit in the second phase 
import os.path
import sys

from Crypto.Hash import SHA3_256

TxLen = 7

def ReadPubParams(filename):
    if os.path.isfile(filename):
        f = open(filename, "r")
        q = int(f.readline())
        p = int(f.readline())
        g = int(f.readline())
        f.close()
        return q, p, g
    else:
        return -1

def checkDSparams(q, p, g):
    check = 0
    warnings.simplefilter('ignore')
    check = sympy.isprime(q)
    warnings.simplefilter('default')
    if check == False: return -1
    
    warnings.simplefilter('ignore')
    check = sympy.isprime(p)
    warnings.simplefilter('default')
    if check == False: return -2
   
    if((p-1)%q != 0): return -3

    k = (p-1)//q
    x = pow(g, k, p)
    if (x==1): return -4
    y = pow(g,q,p)
    if (y!=1): return -4

    if p.bit_length() != 2048: return -5

    if q.bit_length() != 224: return -6
    return 0

def CheckBlock(q, p, g, TxCnt, filename):
    if os.path.isfile(filename):
        f = open(filename, "r")
        block = f.readlines()
        f.close()
        if len(block)%7 != 0:
            print("Incorrect file format")
            return -10000
        block_count = len(block)//7
        for i in range(0, block_count):
            pk = int(block[i*7+2][24:])
            s = int(block[i*7+5][15:])
            h = int(block[i*7+6][15:])
            tx = "".join(block[i*7: i*7+5])
            ver = DS.SignVer(tx.encode('UTF-8'), s, h, q, p, g, pk)
            if ver == -1:
                return -i-1
        return 0
    else:
        print("File does not exist")
        return -10000

##############        
# Student Part
# Test your public parameters with this routine
(q, p, g) = ReadPubParams("pubparams.txt")
# uncomment the next line if you want to check the public parameters
ReturnCode = checkDSparams(q, p, g)
if ReturnCode < 0:
    print("Public parameters are NOT OK: ", ReturnCode)
    sys.exit()
else:
    print("Public parameters are OK")

# This is for generating a random transaction block
# You should have a function with the name "Tx.gen_random_txblock()" in "Tx.py"
TxCnt = 64
Tx.gen_random_txblock(q, p, g, TxCnt, "transactions.txt")

# Test 1
# Check all your transactions in a block
ReturnCode = CheckBlock(q, p, g, TxCnt, "transactions.txt")
if ReturnCode == -10000: print("File Problem")
elif(ReturnCode < 0): print("Signtature Problem in Tranaction number", -ReturnCode)
elif ReturnCode == 0: print("All Transactions Verify")
else: print("Unexpected branching")

# Test 2
# Check PoW of the sample block
proof = PoW.CheckPow(p, q, g, 5, TxCnt, "block_sample.txt")
if proof == "" or proof[:5] != "00000":
    print("PoW is NOT OK:", proof)
else:
    print("PoW is OK:", proof)
    
# Test 3
# This is for generating a PoW for the block in transactions.txt
# You should have a function called "PoW" in file PoW.py
PoWLen = 3   # The number of 0 hexadecimal digits; i.e. PoWLen
block = PoW.PoW(PoWLen, q, p, g, TxCnt, "transactions.txt")
f = open("block.txt", "w")
f.write(block)
f.close()

# Check PoW
proof = PoW.CheckPow(p, q, g, PoWLen, TxCnt, "block.txt")
if proof == "" or proof[:PoWLen] != "0"*PoWLen:
    print("PoW is NOT OK:", proof)
else:
    print("PoW is OK:", proof)

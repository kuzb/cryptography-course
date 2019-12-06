import math
import random
import string
import warnings
import sys
import sympy
import pyprimes
import os.path

import DS
import Tx

    
##############        
# Test 1: Check your public parameters with this routine
def checkDSparams(q, p, g):
    check = 0
    warnings.simplefilter('ignore')
    #check = pyprimes.isprime(q)   # not fast enough
    check = sympy.isprime(q)
    warnings.simplefilter('default')
    if check == False: return -1
    
    warnings.simplefilter('ignore')
    #check = pyprimes.isprime(p)    # not fast enough
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

# Test 2: Chect your public-private key pair
def CheckKeys(q, p, g, alpha, beta):
    if beta == pow(g, alpha, p): return 0
    else: return -1

# Test 3: Check signature for a random message
def CheckSignature(q, p, g, alpha, beta):
    message = DS.random_string(random.randint(32, 512)).encode('UTF-8') # generate a random string for message and convert it to bytes
    (s, r) = DS.SignGen(message, q, p, g, alpha)
    return DS.SignVer(message, s, r, q, p, g, beta)

# Test 4: Verifying the signatures in "TestSet.txt"
def CheckTestSignatures():
    f = open("TestSet.txt", "r")
    q = int(f.readline())
    p = int(f.readline())
    g = int(f.readline())
    beta = int(f.readline())
    for i in range(0,10):
        message = f.readline().rstrip("\n")
        s = int(f.readline())
        r = int(f.readline())
        ReturnCode = DS.SignVer(message.encode('UTF-8'), s, r, q, p, g, beta)
        if ReturnCode != 0:
            f.close()
            return -1
    f.close()
    return 0

# Test 5: generating a single random transaction, sign and verify it 
def CheckTransaction(q, p, g):
    tx = Tx.gen_random_tx(q, p, g)  # generate a random transaction
    transaction = tx.split('\n')    # Split it line by line

    payer_pk = int(transaction[2][25:])  # payer's publick key
    sign_s  = int(transaction[5][15:])   # signature for the transaction (part s)
    sign_r = int(transaction[6][15:])    # signature for the transaction (part r)

    message2sign = '\n'.join(transaction[0:5])+'\n'

    if DS.SignVer(message2sign.encode('utf-8'), sign_s, sign_r, q, p, g, payer_pk)==0:
        return 0
    else:
        return -1

# Test 6: Verifying the signatures of transactions in "transactions.txt"
def CheckBlockofTransactions():
    f = open("transactions.txt", "r")
    tx_block = f.readlines()
    f.close()
    if len(tx_block)%7 != 0:
        print("Incorrect file format")
    else:
        tx_block_count = len(tx_block)//7
        result = [0]*tx_block_count
        for i in range(0, tx_block_count):
            pk = int(tx_block[i*7+2][24:])
            s = int(tx_block[i*7+5][15:])
            r = int(tx_block[i*7+6][15:])
            tx = "".join(tx_block[i*7: i*7+5])
            result[i] = DS.SignVer(tx.encode('UTF-8'), s, r, q, p, g, pk)
    return result        
    
##### This part executes
# Generate or read the public parameters
# You need to have a routine named GenerateOrRead that reads q, p, g from "pubparams.txt" if exists
# Otherwise, it should generate public parameters and write them to "pubparams.txt" 
(q, p, g) = DS.GenerateOrRead("pubparams.txt")  
# DS.GenerateTestSignatures(q, p, g)  # Generate sample signatures (Students do not uncomment this)

# Testing part
# Test 1: Test public parameters
ReturnCode = checkDSparams(q, p, g)
if ReturnCode == 0: print("Public parameters: Passed!")
elif ReturnCode == -1: print("q is not prime"); sys.exit()
elif ReturnCode == -2: print("p is not prime"); sys.exit()
elif ReturnCode == -3: print("q does not divide p"); sys.exit()
elif ReturnCode == -4: print("g is not a generator"); sys.exit()
elif ReturnCode == -5: print("p is not 2048 bit"); sys.exit()
elif ReturnCode == -6: print("q is not 224 bit"); sys.exit()    
  
# Test 2: Check a public-private key pair 
(alpha, beta) = DS.KeyGen(q, p, g) # generate key pair
ReturnCode = CheckKeys(q, p, g, alpha, beta)
if ReturnCode == 0: print("Public/private key pair: Passed!")
else: print("Public/private key pair: Failed!"); sys.exit()

# Test 3: Check the signature generation-verification for a randomly generated message
ReturnCode = CheckSignature(q, p, g, alpha, beta)
if ReturnCode == 0: print("Signature generation: Passed!")
else: print("Signature generation: Failed!"); sys.exit()

# Test 4: Verifying the signatures in "TestSet.txt"
if (CheckTestSignatures() == 0): print("Sample signatures test: Passed!")
else: print("Sample signatures test: Failed!"); sys.exit()

# Test 5: generating a single random transaction, sign and verify it
if (CheckTransaction(q, p, g) == 0): print("Transaction signature verifies: Passed!")
else: print("Transaction signature DOES NOT verify: Failed!"); sys.exit()


# Test 6: Verifying the signatures of transactions in "transactions.txt"
result = CheckBlockofTransactions()
if -1 not in result: print("All transactions verified successfully: Passed!")
else:
    for i in range(len(result)):
        if result[i] == -1:
            print("Failure: tsransaction", i+1, "does not verify: Failed!")
    sys.exit()

import random
import hashlib

def PoW(PoWLen, filename):
    f = open(filename, "r")
    block = f.readlines()
    block = "".join(block)
    block += "Nonce: "

    while True:
        nonce = str(random.getrandbits(128)) + "\n"
        possible = block + nonce
        hashed = hashlib.sha3_256(possible.encode('UTF-8')).hexdigest()

        if hashed[0:PoWLen] == "0" * PoWLen:
            break

    return possible

def AddBlock2Chain(PoWLen, TxCnt, block_candidate, PrevBlock):
    if PrevBlock == 0:
         block_candidate += "Previous Hash: b '0'" + "\n"
    if PrevBlock != 0 and type(PrevBlock) != int:
        hashed = hashlib.sha3_256(PrevBlock.encode('UTF-8')).hexdigest()
        block_candidate += "Previous Hash: " + str(hashed) + "\n"

    block_candidate += "Nonce: "
    possible = block_candidate
    while True:
        nonce = str(random.getrandbits(128)) + "\n"
        possible += "Nonce: " + nonce
        hashed = hashlib.sha3_256(possible.encode('UTF-8')).hexdigest()

        if hashed[0:PoWLen] == "0" * PoWLen:
            break

    return possible
    

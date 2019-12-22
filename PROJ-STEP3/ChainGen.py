from multiprocessing import Pool
from Crypto.Hash import SHA3_256
from MerkleTree import MerkleTree

def getDigest(message):
    return (SHA3_256.new(message)).digest()

def getHexdigest(message):
    return (SHA3_256.new(message)).hexdigest()

def AddBlock2Chain(PoWLen, TxCount, BlockCandidate, PrevBlock):
    if len(PrevBlock) == 0:
        PrevPoW = '00000000000000000000'   
    else:
        root = getRoot(TxCount, PrevBlock, 9) 
       
        # Getting nonce from the lastline
        nonce = int(''.join(filter(str.isdigit, PrevBlock[-1])))
        # Getting PoW of previous Block from 2nd lastline
        PrevPoW =  ( PrevBlock[-2].rsplit(': ', 1)[1] ).strip('\n')

        digest = root + PrevPoW.encode('utf-8') + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder = 'big')
        PrevPoW = SHA3_256.new(digest).hexdigest()
    
    root = getRoot(TxCount, BlockCandidate, 9) 
    
    text = "".join(BlockCandidate) 
    text += "Previous PoW: " + str(PrevPoW)
    text += "\n"
    
    nonce = getNonce(root, PrevPoW, PoWLen)
    
    text += "Nonce: " + str(nonce) 
    text += " \n"
    return text, PrevPoW   

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
    

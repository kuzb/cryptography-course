import random
from DS import SignGen, KeyGen

def gen_random_tx(q, p, g):
    transaction = "*** Bitcoin transaction ***\n"
    serial = random.getrandbits(128)
    transaction += "Serial number: " + str(serial) + "\n"

    payerAlpha, payerBeta = KeyGen(q, p, g)

    transaction += "Payer Public Key (beta): " + str(payerBeta) + "\n"

    payeeAlpha, payeeBeta = KeyGen(q, p, g)

    transaction += "Payee Public Key (beta): " + str(payeeBeta) + "\n"

    amount = random.randint(1, 1000000)
    transaction += "Amount: " + str(amount) + "\n"

    # Generate signatures for payer
    s, r = SignGen(str(transaction).encode('utf-8'), q, p, g, payerAlpha)

    transaction += "Signature (s): " + str(s) + "\n"
    transaction += "Signature (r): " + str(r) + "\n"

    return transaction

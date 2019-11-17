from utils import *

# Yield successive n-sized chunks from l.
def giveChunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


def cycles(poly, poly_s):
    length = 1000
    degree = len(poly) - 1
    start = [0] * degree

    for i in range(0, degree):            # for random initial state
        start[i] = random.randint(0, 1)
    
    print("Initial state: ", start)

    keystream = [0]*length

    for i in range(0, length):
        keystream[i] = LFSR(poly, start)

    chunks = list(giveChunks(keystream, len(poly) - 1))
    period = FindPeriod(keystream)

    if period == (2**degree) - 1:
        print(poly_s, 'does generate maximum period sequence(does full cycle), and its\' period is', period)
    else:
        print(poly_s, 'does not generate maximum period sequence(does not full cycle)(is not a primitive polynomial), and its\' period is', period)

    print('These are the chunks of streams generated within the period')
    [print(n) for n in chunks[:period]]

    print()

    print(BM(keystream))


dic1 = [[1, 0, 0, 1, 0, 1], 'p1(x) = x^5 + x^2 + 1']
dic2 = [[1, 0, 1, 1, 0, 1], 'p2(x) = x^5 + x^3 + x^2 + 1']


print('p1(x) = x^5 + x^2 + 1 can be represented as', dic1[0])
print()
cycles(dic1[0], dic1[1])
print()

print('p2(x) = x^5 + x^3 + x^2 + 1 can be represented as', dic2[0])
print()
cycles(dic2[0], dic2[1])

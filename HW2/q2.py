from utils import *

n = 333837116253674643166082492900

a_list = [57063337401967433471889139534,
          176622984297114106732586191098, 320736651991764172584335713727]
b_list = [397555361861029295385484594412,
          84172329859897226978948124629, 30472957776104045808802882504]

print("Solving ax = b mod n")

for i in range(3):
    print('For values \na =', a_list[i], '\nb =', b_list[i], '\nn =', n)
    gcd_val = gcd(a_list[i], n)
    print('gcd(a,n) is', gcd_val)
    if gcd_val == 1:
        print('There is only one solution because gcd(a,b) is 1')
        print('Solution:\nx is', (modinv(a_list[i], n) * b_list[i]) % n)
        print('\n')
    else:
        if b_list[i] % gcd_val != 0:
            print('There is no solution because b/gcd(a,n) have non zero remainder i.e. b cannot be divided by gcd(a,n):', gcd_val)
            print('\n')
        elif b_list[i] % gcd_val == 0:
            print('There will be', gcd_val, 'solutions')
            print('Solutions:')
            for i in range(gcd_val):
                aDividedByGCD = a_list[i] // gcd_val
                bDividedByGCD = b_list[i] // gcd_val
                nDividedByGCD = n // gcd_val
                X = (modinv(aDividedByGCD, nDividedByGCD)
                     * bDividedByGCD) % nDividedByGCD
                print('X', i, ' is ', X + (i * nDividedByGCD), sep="")
            print('\n')

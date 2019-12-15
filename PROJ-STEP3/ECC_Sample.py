# Run "pip install ecpy" if ecpy is not installed
import random
import sys
from ecpy.curves import Curve

# The code segments here demonstrate how you setup a curve and perform
# elliptic curve arithmetic

# Obtain the standard curve 'secp256k1' used in many applications
# including bitcoin
# obtain its parameters
E = Curve.get_curve('secp256k1')
a = E.a
b = E.b
p = E.field
print("Curve Parameters:\n", E)

# Obtain the curve order n and the base (generator point) P
# and print x and y coordinates of P 
n = E.order
P = E.generator
print("(x_p, y_p): ", P.x, P.y)


# Obtain two random points on the curve
# by calculating random multiples of P
x = random.randint(2,n-1)
y = random.randint(2,n-1)
Q = x*P
R = y*P
# Add two random points
S = Q+R

print("(x_q, y_q): ", Q.x, Q.y)
print("(x_r, y_r): ", R.x, R.y)
print("(x_s, y_s): ", S.x, S.y)

#Check if Q, R, and S are reallypoints on the curve E
print("Is Q on the curver?", (Q.y*Q.y)%p == (Q.x**3+a*Q.x+b)%p)
print("Is R on the curver?", (R.y*R.y)%p == (R.x**3+a*R.x+b)%p)
print("Is S on the curver?", (S.y*S.y)%p == (S.x**3+a*S.x+b)%p)


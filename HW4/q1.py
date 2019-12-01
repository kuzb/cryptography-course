from RSA_OAEP import *

# public key encryption
e = 65537

# public key 
N = 70212284026476551287497867344660173062242619935306997607985987428352052911293

# ciphertext
c = 60400943706823506830284280114139818288715016023417103465230780522075862090739

# Ranges for 8 bit int
k1 = 2**(k0-1)
k2 = 2**k0-1

# Pin is 4 digit so it has to be between 1000 and 9000
for pin in range(1000, 9999):
    for r in range(k1,k2):
        if c == RSA_OAEP_Enc(pin, e, N, r):
            print("Pin is found:", pin)


print("----- Starting a new run -----")


Pq.<x> = PolynomialRing(GF(311))
ring = Pq.quotient(x^4 + 1); ring
a = ring.gen()

m = 1

s = -1 -a -a^2 + a^3

e_prime = 1 -2*a^2 -2*a^3
e_prime_prime = 16 -2*a +2*a^2 -7*a^3
a0 = 297 + 69*a + 253*a^2 + 22*a^3
b0 = 220 + 18*a + 292*a^2 + 264*a^3
v = 2 + a - a^3
t = 7

a0_mul_v = a0 * v

t_mul_e_prime = e_prime * t
a = a0_mul_v + t_mul_e_prime
b0_mul_v = b0 * v
t_mul_e_prime_prime = e_prime_prime * t
b = b0_mul_v + t_mul_e_prime_prime

c0 = b + m
c1 = -a

decrypted = c0 + c1 * s

print(decrypted)
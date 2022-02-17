print("----- Starting a new run -----")

q = 16041433

Pq.<x> = PolynomialRing(GF(q))
ring = Pq.quotient(x^4 + 1); ring
a = ring.gen()

m = 1

s = -1+1*a^1+-1*a^2+-3*a^3

e_prime = 0+0*a^1+1*a^2+1*a^3
e_prime_prime = 5+-4*a^1+0*a^2+-3*a^3
a0 = 9080416+7408485*a^1+1430815*a^2+6810925*a^3
b0 = 7764922+12775315*a^1+1288603*a^2+8094449*a^3
v = -1+-2*a^1+0*a^2+2*a^3
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
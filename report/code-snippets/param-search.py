from math import sqrt, floor, log2

N = 512
p = 127
r = 3.2
SEC = 40
C_m = 8.6
n = 3

# The values for the formulas
csec = 9 * N**2 * SEC**4 * 2**(SEC + 8)
Y = p/2 + p * (4 * C_m * r**2 * N**2 + 2 * sqrt(N) * r + 4 * C_m * r**2 * N**2)
Z = C_m * N**2 * n**2 * csec**2 * Y**2 + n * csec * Y

q_size = 2 * Z * (1 + 2**SEC)
print("The bit size of q should be above: ",
      floor(log2(q_size)))

chosen_q = int("""6440092097492369874468694478456476902429
935263779065830479393474203066496323859298183983608879""".replace('\n', ''))
gamma = 1.005
t_prime = sqrt(N * (log2(chosen_q)/log2(gamma)))
r_bound = max(3.2, 1.5 * gamma**(-t_prime) * chosen_q**(1 - (N / t_prime)))
print("The value of the randomness r should be above: ", r_bound)

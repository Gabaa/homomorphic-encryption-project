from estimator import *
from estimator.lwe_parameters import *
from estimator.nd import *

N = 2048
q = 80708763
Xe = NoiseDistribution(3.2)
Xs = NoiseDistribution(3.2)
m = 2*N

params = LWEParameters(N, q, Xs, Xe, m, tag="params")
result = LWE.estimate.rough(params)
print(result)

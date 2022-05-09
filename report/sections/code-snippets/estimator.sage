from estimator import *
from estimator.lwe_parameteres import LWEparameters
from estimator.nd import NoiseDistribution

n = 2048
q = 80708763
Xe = NoiseDistribution(3.2)
Xs = NoiseDistribution(3.2)
m = 2*n

params = LWEParameters(n, q, Xs, Xe, m, tag="params")
result = LWE.estimate.rough(params)
print(result)

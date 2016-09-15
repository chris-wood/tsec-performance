import sys
import subprocess
import time
from datetime import datetime

def argon2(params):
    pass

class Argon2Params(object):
    def __init__(self, t = 1, m = 1, d = 1):
        self.t = t
        self.m = m
        self.d = d

    def neighbors(self):
        params = []
        if self.t > 1:
            params.append(Argon2Params(self.t - 1, self.m, self.d))
        params.append(Argon2Params(self.t + 1, self.m, self.d))

        if self.m > 1:
            params.append(Argon2Params(self.t, self.m - 1, self.d))
        params.append(Argon2Params(self.t, self.m + 1, self.d))
       
        if self.d > 1:
            params.append(Argon2Params(self.t, self.m, self.d - 1))
        params.append(Argon2Params(self.t, self.m, self.d + 1))

        return params

def scrypt(prog, params):
    process = subprocess.Popen([prog, "scrypt", str(params.N), str(params.r), str(params.p)], stdout=subprocess.PIPE)
    pout, err = process.communicate()
    return float(pout) / 1000.0 # ns to us

class ScryptParams(object):
    def __init__(self, N = 1, r = 1, p = 1):
        self.N = N
        self.r = r
        self.p = p

    def neighbors(self):
        params = []
        if self.N > 1:
            params.append(ScryptParams(self.N - 1, self.r, self.p))
        params.append(ScryptParams(self.N + 1, self.r, self.p))

        if self.r > 1:
            params.append(ScryptParams(self.N, self.r - 1, self.p))
        params.append(ScryptParams(self.N, self.r + 1, self.p))
       
        if self.p > 1:
            params.append(ScryptParams(self.N, self.r, self.p - 1))
        params.append(ScryptParams(self.N, self.r, self.p + 1))

        return params

### https://en.wikipedia.org/wiki/Hill_climbing
def optimize(prog, hasher, initialParams, P):
    current = initialParams
    seen = []
    while True:
        L = current.neighbors()
        nextEval = -1
        nextNode = None

        for param in L:
            if param in seen: # don't repeat old params
                continue
            seen.append(param)
            thetime = hasher(prog, param)
            if nextEval == -1:
                nextNode = param
                nextEval = thetime
            elif thetime > P and thetime < nextEval:
                nextNode = param
                nextEval = thetime
        currentTime = hasher(prog, current)
        print currentTime, P
        if nextEval == -1 or (currentTime > P and currentTime < nextEval):
            return current
        current = nextNode

prog = sys.argv[1]
P = float(sys.argv[2])
params = optimize(prog, scrypt, ScryptParams(), P)
print params

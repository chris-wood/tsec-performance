import sys
import subprocess
import time
import random
from datetime import datetime

def argon2(prog, params):
    process = subprocess.Popen([prog, "ARGON2", str(params.t), str(params.m), str(params.d)], stdout=subprocess.PIPE)
    pout, err = process.communicate()
    return float(pout) / 1000.0 # ns to us

class Argon2Params(object):
    def __init__(self, t = 3, m = 12, d = 1):
        self.t = t
        self.m = m
        self.d = d

    def neighbors(self):
        params = []
        if self.t > 1:
            params.append(Argon2Params(self.t >> 1, self.m, self.d))
        params.append(Argon2Params(self.t << 1, self.m, self.d))

        if self.m > 1:
            params.append(Argon2Params(self.t, self.m - 1, self.d))
        params.append(Argon2Params(self.t, self.m + 1, self.d))
       
        if self.d > 1:
            params.append(Argon2Params(self.t, self.m, self.d - 1))
        params.append(Argon2Params(self.t, self.m, self.d + 1))

        return params

    def __repr__(self):
        return "(%d, %d, %d)" % (self.t, self.m, self.d)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.t == other.t and self.m == other.m and self.d == other.da
        else:
            return False

    def __cmp__(self, other):
        if isinstance(other, self.__class__):
            return self.t == other.t and self.m == other.m and self.d == other.da
        else:
            return False

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
        if self.N >> 2 > 1:
            params.append(ScryptParams(self.N >> 2, self.r, self.p))
        params.append(ScryptParams(self.N << 2, self.r, self.p))

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
    seen = set()
    nextSet = []
    while True:

        L = current.neighbors()
        for p in nextSet:
            L.append(p)

        random.shuffle(L)
        nextSet = []

        nextEval = -1
        nextNode = None


        for param in L:
            if str(param) not in seen: # don't repeat old params
                seen.add(str(param))
                for p in param.neighbors():
                    nextSet.append(p)
                thetime = hasher(prog, param)
                if nextEval == -1:
                    nextNode = param
                    nextEval = thetime
                elif thetime > P and thetime < nextEval:
                    nextNode = param
                    nextEval = thetime

        currentTime = hasher(prog, current)
        if nextEval == -1:
            return current
        if currentTime > P and currentTime < nextEval:
            return current
        current = nextNode

        print current, len(L), nextEval
    
    return current

prog = sys.argv[1]
P = float(sys.argv[2])
params = optimize(prog, argon2, Argon2Params(), P)
print params

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
            params.append(Argon2Params(self.t - 1, self.m, self.d))
        params.append(Argon2Params(self.t + 1, self.m, self.d))

        if self.m > 1:
            params.append(Argon2Params(self.t, self.m - 1, self.d))
        params.append(Argon2Params(self.t, self.m + 1, self.d))
     
        '''
        if self.d > 1:
            params.append(Argon2Params(self.t, self.m, self.d - 1))
        params.append(Argon2Params(self.t, self.m, self.d + 1))
        '''

        return params

    def successors(self):
        params = []
        params.append(Argon2Params(self.t + 1, self.m, self.d))
        params.append(Argon2Params(self.t, self.m + 1, self.d))
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

def optimize_bnb(prog, hasher, initialParams, target):
    pass

### https://en.wikipedia.org/wiki/Hill_climbing
def optimize_hill(prog, hasher, initialParams, target):
    current = initialParams
    currentTime = -1
    seen = set()
    nextSet = []
    while True:

        L = current.neighbors()
        for p in nextSet:
            L.append(p)

        random.shuffle(L)
        if len(L) > 100:
            L = L[0:100]
        nextSet = []

        nextEval = -1
        nextNode = None

        for param in L:
            if str(param) not in seen: # don't repeat old params
                seen.add(str(param))
                thetime = hasher(prog, param)
                for p in param.neighbors():
                    nextSet.append(p)

                if thetime > nextEval and thetime < target:
                    nextNode = param
                    nextEval = thetime

        thetime = hasher(prog, current)
        if thetime > nextEval and thetime < target:
            return current, currentTime

        # [currentTime ... nextEval ... target]
        if nextEval > currentTime and nextEval < target:
            current = nextNode
            currentTime = nextEval
        elif thetime > currentTime and thetime < target: # [nextEval ... currentTime ... target]
            current = current
            currentTime = thetime

        print current, currentTime, len(L)
    
    return current, currentTime

prog = sys.argv[1]
P = float(sys.argv[2])
params, thetime = optimize_hill(prog, argon2, Argon2Params(), P)
print params, thetime

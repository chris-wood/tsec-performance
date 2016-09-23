import sys
import subprocess
import time
import random
from datetime import datetime

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

    def successors(self, bound = None):
        params = []
        if bound == None or self.t < bound.t:
            params.append(Argon2Params(self.t + 1, self.m, self.d))
        if bound == None or self.m < bound.m:
            params.append(Argon2Params(self.t, self.m + 1, self.d))
        if bound == None or self.d < bound.d:
            params.append(Argon2Params(self.t, self.m, self.d + 1))
        return params

    def process(self, prog):
        process = subprocess.Popen([prog, "ARGON2", str(self.t), str(self.m), str(self.d)], stdout=subprocess.PIPE)
        pout, err = process.communicate()
        return float(pout) / 1000.0 # ns to us

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

def profile(prog, initialParams, boundParams):
    ''' Simple DFS traversal of the parameter space...
    '''
    queue = [initialParams]
    results = {}
    visited = set()
    while len(queue) > 0:
        curr = queue.pop(0)
        if str(curr) not in visited:
            visited.add(str(curr))
            print >> sys.stderr, "Processing %s" % repr(curr)
            delta = curr.process(prog)
            results[str(curr)] = delta

            for nextParams in curr.successors(boundParams):
                queue.append(nextParams)
    return results
    

prog = sys.argv[1]
initialParams = Argon2Params(1, 1, 1)
boundParams = Argon2Params(10, 10, 2)
results = profile(prog, initialParams, boundParams)
print results

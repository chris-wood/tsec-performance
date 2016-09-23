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

    def successors(self):
        params = []
        params.append(Argon2Params(self.t + 1, self.m, self.d))
        params.append(Argon2Params(self.t, self.m + 1, self.d))
        #params.append(Argon2Params(self.t, self.m, self.d + 1))
        return params
    
    def process(self, prog, N = 5):
        total = 0.0
        for i in range(N):
            process = subprocess.Popen([prog, "ARGON2", str(self.t), str(self.m), str(self.d)], stdout=subprocess.PIPE)
            pout, err = process.communicate()
            total += (float(pout) / 1000.0)
        return total / float(N)

    def __repr__(self):
        return "(%d, %d, %d)" % (self.t, self.m, self.d)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.t == other.t and self.m == other.m and self.d == other.d
        else:
            return False

    def __cmp__(self, other):
        if isinstance(other, self.__class__):
            return self.t == other.t and self.m == other.m and self.d == other.d
        else:
            return False


class ScryptParams(object):
    def __init__(self, N = 1, r = 1, p = 1):
        self.N = N
        self.r = r
        self.p = p

    def process(self, prog, N = 5):
        total = 0.0
        for i in range(N):
            process = subprocess.Popen([prog, "scrypt", str(self.N), str(self.r), str(self.p)], stdout=subprocess.PIPE)
            pout, err = process.communicate()
            total += (float(pout) / 1000.0)
        return total / N

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

    def successors(self):
        params = []
        params.append(ScryptParams(self.N + 1, self.r, self.p))
        params.append(ScryptParams(self.N, self.r + 1, self.p))
        return params

    def __repr__(self):
        return "(%d, %d, %d)" % (self.N, self.r, self.p)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.N == other.N and self.r == other.r and self.p == other.p
        else:
            return False

    def __cmp__(self, other):
        if isinstance(other, self.__class__):
            return self.N == other.N and self.r == other.r and self.p == other.p
        else:
            return False

### https://en.wikipedia.org/wiki/Branch_and_bound
def optimize_bnb(prog, initialParams, target):
    pass

### https://en.wikipedia.org/wiki/Hill_climbing
def optimize_hill(prog, initialParams, target):
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
            if param not in seen: # don't repeat old params
                seen.add(param)
                thetime = param.process(prog)
                for p in param.neighbors():
                    nextSet.append(p)

                if thetime > nextEval and thetime < target:
                    nextNode = param
                    nextEval = thetime

        thetime = current.process(prog)
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

def optimize_dfs(prog, initialParams, target, epsilon = 0.1):
    queue = [(initialParams, 0)]
    visited = set()
    visited.add(str(initialParams))
    results = {}
    while len(queue) > 0:
        (current, lasttime) = queue.pop()
        thetime = current.process(prog)

        if thetime < P and abs(thetime - lasttime) >= epsilon:
            for nextParams in current.successors():
                if str(nextParams) not in visited:
                    visited.add(str(nextParams))
                    queue.append((nextParams, thetime))
        else:
            results[current] = lasttime
    return results

def find_min_params(results):
    max_key = results.keys()[0]
    max_val = results[max_key]
    for k in results:
        v = results[k]
        if v > max_val:
            max_key = k
            max_val = v
    return max_key


prog = sys.argv[1]
#scrypt = ScryptParams(1, 1, 1)
#print scrypt.process(prog)

P_list = [2, 4, 8, 16, 32, 64, 128]
targets = map(lambda P : int((float(1500) / (P * 1000000)) * 1000000), P_list)
for i, P in enumerate(targets):
    initialParams = Argon2Params(1, 1, 1)
    results = optimize_dfs(prog, initialParams, P)
    print "argon2", P_list[i], find_min_params(results)

    #initialParams = ScryptParams(1, 1, 1)
    #results = optimize_dfs(prog, initialParams, P)
    #print "scrypt", P_list[i], find_min_params(results)


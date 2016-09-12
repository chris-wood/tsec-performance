# general stuff
import sys
import os
import random
import time
from sigfig import *

from matplotlib.font_manager import FontProperties

# matplot lib stuff
import matplotlib.lines as mlines
import matplotlib as mpl
import matplotlib.pyplot as plt
import math
import numpy as np

dataFileName = sys.argv[1]
lengths = []
algTimes = {}

with open(dataFileName, "r") as f:
    for line in f:
        data = line.strip().split(",")
        alg = data[0]
        length = int(data[1])
        avgTime = float(data[2])
        maxP = float(length) / (avgTime / 1000000000) # must convert the nanoseconds to seconds
        maxP = int(round_sig(maxP, 5))

        if length not in lengths:
            lengths.append(length)
        if alg not in algTimes:
            algTimes[alg] = []
        algTimes[alg].append(maxP)

ind = np.arange(0, len(lengths))
#ind = np.array(lengths)
width = float(1) / len(algTimes.keys()) - 0.1

## debug
print ind, width
print lengths, algTimes

fig, ax = plt.subplots()

colors = ['r', 'b', 'y', 'g']
colorIndex = 0
plots = []
for alg in algTimes:
    plot = ax.bar(ind + (colorIndex * width), algTimes[alg], width=width, color=colors[colorIndex])
    plots.append(plot)
    colorIndex += 1

ax.set_xlabel('Packet Size [B]')
ax.set_ylabel('Throughput Capacity [packets/second]')
ax.set_title('')
ax.set_xticks(ind + 2*width)
ax.set_xticklabels(lengths)

plt.legend( (plots[0][0], plots[1][0]), (algTimes.keys()[0], algTimes.keys()[1]) )

plt.show()
#plt.savefig(figureFileName)

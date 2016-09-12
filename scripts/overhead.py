# general stuff
import sys
import os
import random
import time

from matplotlib.font_manager import FontProperties

# matplot lib stuff
import matplotlib.lines as mlines
import matplotlib as mpl
import matplotlib.pyplot as plt
import math
import numpy as np

dataFileName = sys.argv[1]

# Run the protocol, end to end
avg1s = []
err1s = []
avg2s = []
err2s = []
avg3s = []
err3s = []
avg4s = []
err4s = []
lengths = []
factor = 1000

with open(dataFileName, "r") as f:
    for line in f:
        data = line.strip().split(",")
        N = int(data[0])
        lengths.append(N)

        time1, time1sd = float(data[1]) / factor, float(data[2]) / factor
        avg1s.append(time1)
        err1s.append(time1sd)

        time2, time2sd = float(data[3]) / factor, float(data[4]) / factor
        avg2s.append(time2)
        err2s.append(time2sd)

        time3, time3sd = float(data[5]) / factor, float(data[6]) / factor
        avg3s.append(time3)
        err3s.append(time3sd)

        time4, time4sd = float(data[7]) / factor, float(data[8]) / factor
        avg4s.append(time4)
        err4s.append(time4sd)

ind = np.arange(min(lengths), max(lengths) + 1)
print min(lengths), max(lengths), lengths
width = 0.2

fig, ax = plt.subplots()
p1 = ax.bar(ind, avg1s, width=width, color='r', yerr=err1s)
#p2 = plt.bar(lengths, avg2s, width=0.35, color='y', bottom=avg1s, yerr=err2s) #, yerr=menStd)
#p3 = plt.bar(lengths, avg3s, width=0.35, color='g', bottom=avg2s, yerr=err3s) #, yerr=menStd)
#p4 = plt.bar(lengths, avg4s, width=0.35, color='b', bottom=avg3s, yerr=err4s) #, yerr=menStd)
p2 = ax.bar(ind + width, avg2s, width=width, color='y', yerr=err2s) #, yerr=menStd)
p3 = ax.bar(ind + 2*width, avg3s, width=width, color='g', yerr=err3s) #, yerr=menStd)
p4 = ax.bar(ind + 3*width, avg4s, width=width, color='b', yerr=err4s) #, yerr=menStd)

#font = {'fontname': 'Verdana'}
# **font

ax.set_xlabel('Number of Segments')
ax.set_ylabel('Time (us)')
ax.set_title('')
ax.set_xticks(ind + 2*width)
ax.set_xticklabels(lengths)

#plt.ylabel('Time (s)')
#plt.xlabel('Number of Name Components')
# plt.title('TODO')
# plt.xticks(ind+width/2., ('Hash Obfuscation', 'G2', 'G3', 'G4', 'G5') )
# plt.yticks(np.arange(0,81,10))
plt.legend( (p1[0], p2[0], p3[0], p4[0]), ('Step 1', 'Step 2', 'Step 3', 'Step 4') )

# plt.tight_layout()
plt.show()
#plt.savefig(figureFileName)

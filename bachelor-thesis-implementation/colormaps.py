import matplotlib.pyplot as plt
import matplotlib as mp
import pandas as pd
import numpy as np
from scipy import sparse

PATH = "~/ETH/Bachelor Thesis/bachelor-thesis-implementation/bachelor-thesis-implementation/src/main/resources/data/"
SAVE_TO = "~/ETH/Bachelor Thesis/bachelor-thesis/pictures/"
ACCURANCY = [0, 0, 0]
files = ["data.csv", "VDS_MS_310809_27_0210.csv", "Gowalla_totalCheckins.txt"]
data_sets = [pd.read_csv(PATH + files[0], delimiter=' ').to_numpy(), 
             pd.read_csv(PATH + files[1], delimiter=',').to_numpy(), 
             pd.read_csv(PATH + files[2], delimiter='\t').to_numpy()]
x_s = [1, 4, 2]
y_s = [2, 5, 3]

for i in range(1):
    print("PLOT ", i)
    data = data_sets[i]
    y = [k for k in data[:, x_s[i]] if not np.isnan(k)]
    x = [k for k in data[:, y_s[i]] if not np.isnan(k)]
    print(np.mean(x), np.mean(y))
    
    x_min = min(x) - 1
    y_min = min(y) - 1
    print(x_min, max(x))
    print(y_min, max(y))
    n_x = round((max(x) - x_min + 1) * 10**ACCURANCY[i], 0)
    n_y = round((max(y) - y_min + 1) * 10**ACCURANCY[i], 0)
    X, Y = np.meshgrid(x,y, sparse=True)
    C = np.zeros([np.size(X, 1), np.size(Y, 0)])

    counter = 0
    loc_x = X - x_min
    loc_y = Y - y_min
    for j in range(np.size(X,1)):
        C[int(round(loc_x[0,j], 0)), int(round(loc_y[j,0],0))] += 1
        counter += 1

    print(counter)

    cmap = plt.cm.inferno
    cmaplist = [cmap(i) for i in range(cmap.N)]
    cmaplist[0] = (1, 1, 1, 1.0) # white for background
    cmap = mp.colors.LinearSegmentedColormap.from_list('Custom cmap', cmaplist)
    
    plot = plt.pcolormesh(X, Y, C, cmap=cmap)
    plt.tick_params(axis='x', bottom=False, labelbottom=False)
    plt.tick_params(axis='y', left=False, labelleft=False)
    plt.colorbar(plot)
    plt.savefig(files[i].split('.')[0] + ".pdf")
    plt.close()

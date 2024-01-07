import matplotlib.pyplot as plt
import matplotlib as mp
import pandas as pd
import numpy as np
from scipy import sparse

PATH = "~/ETH/Bachelor Thesis/bachelor-thesis-implementation/bachelor-thesis-implementation/src/main/resources/data/"
ACCURANCY = [1, 1, 3]
files = ["data.csv", "VDS_MS_310809_27_0210.csv", "Gowalla_totalCheckins.txt"]
data_sets = [pd.read_csv(PATH + files[0], delimiter=' ').to_numpy(), 
             pd.read_csv(PATH + files[1], delimiter=',').to_numpy(), 
             pd.read_csv(PATH + files[2], delimiter='\t').to_numpy()]
x_s = [1, 4, 3]

for i in range(3):
    print("PLOT ", i)
    data = data_sets[i]
    x = [k for k in data[:, x_s[i]] if not np.isnan(k)]
    print(np.mean(x))
    
    x_min = min(x) - 1
    print(x_min, max(x))
    n_x = int(round((max(x) - x_min + 1) * 10**ACCURANCY[i], 0))
    X = np.linspace(x_min, max(x), n_x)
    C = np.zeros(n_x)

    counter = 0
    loc_x = np.array(x) - x_min
    for j in range(np.size(x)):
        C[int(round(loc_x[j] * 10**ACCURANCY[i], 0))] += 1
        counter += 1
    print(counter)
    
    marker_size = [c / 10 for c in C]
    plt.scatter(X, C, marker='.', c='black', s=marker_size)
    plt.xlabel('Longitude')
    plt.ylabel('Number of data points')
    #plt.tick_params(axis='x', bottom=False, labelbottom=False)
    #plt.tick_params(axis='y', left=False, labelleft=False)
    plt.savefig(files[i].split('.')[0] + ".pdf")
    plt.close()

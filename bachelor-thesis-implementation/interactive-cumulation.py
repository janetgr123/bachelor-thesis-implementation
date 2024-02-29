import pandas as pd
from os.path import exists

PATH = "src/test/resources/data/" 
SUBFOLDER = "dataForPlots/"
indices = [1]

# data size vs. time
methods = ["trapdoor", "search"]
for method in methods:
    for index in indices:
        l = {}
        list = []
        for i in range(2):
            file = PATH + SUBFOLDER + method +"-" + str(index) + "-dataSizeVsTime.csv"
            if i == 1:
                file = PATH + SUBFOLDER + method +"2-" + str(index) + "-dataSizeVsTime.csv"
            df = pd.read_csv(file, header=None)
            for (d,t) in df.values:
                d = int(d)
                if i == 0:
                    l[d] = t
                else:
                    tmp = l[d]
                    l[d] = tmp + t
                    list.append((d, l[d]))
        new_df = pd.DataFrame(list)
        new_df.to_csv(PATH + SUBFOLDER + method + "-" + str(index) + "-dataSizeVsTime-cum.csv", header=False, index=False)


        
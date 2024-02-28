import pandas as pd
from os.path import exists

PATH = "src/test/resources/data/" 
SUBFOLDER = "dataForPlots/"
indices = [56]
#indices2 = list(range(48, 141, 4))
#indices += indices2

# data size vs. time
methods = ["trapdoor", "search"]
for index in indices:
    l = {}
    list = []
    for method in methods:
        file = PATH + SUBFOLDER + method +"-" + str(index) + "-dataSizeVsTime.csv"
        if(exists(file)):
            df = pd.read_csv(file, header=None)
            if method == "trapdoor":
                for (d,t) in df.values:
                    l[d] = t
            else:
                for (d,t) in df.values:
                    tmp = l[d]
                    l[d] = tmp + t
                    list.append((d, l[d]))
    new_df = pd.DataFrame(list)
    new_df.to_csv(PATH + SUBFOLDER + method + "-" + str(index) + "-dataSizeVsTime-total.csv", header=False, index=False)


        
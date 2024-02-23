import pandas as pd
from os.path import exists

PATH = "src/test/resources/data/" 
SUBFOLDER = "dataForPlots/"
indices = list(range(0,45,4))
indices.append(56)
indices.append(60)
indices.append(72)
indices.append(76)

# data size vs. time
methods = ["buildIndex", "trapdoor", "search", "trapdoor2", "search2"]
for method in methods:
    for index in indices:
        file = PATH + method +"-" + str(index) + ".csv"
        if(exists(file)):
            df = pd.read_csv(file)
            df = df[df['emm'] != 'emm']
            data_sizes = df['data size'].unique()
            list = []
            for data_size in data_sizes:
                rows = df.loc[df['data size'] == data_size]
                average = rows['time [ns]'].astype(float).mean(axis=0)
                list.append((data_size, average))
            new_df = pd.DataFrame(list)
            new_df.to_csv(PATH + SUBFOLDER + method + "-" + str(index) + "-dataSizeVsTime.csv", header=False, index=False)


# encrypted index size (bytes) and percentage padding
df = pd.read_csv(PATH + "overheadEncryptedIndex-" + str(index) + ".csv")
df = df[df['emm'] != 'emm']
data_sizes = df['data size'].unique()
list = []
list2 = []
for data_size in data_sizes:
    rows = df.loc[df['data size'] == data_size]
    average = rows['size encrypted index'].astype(float).mean(axis=0)
    list.append((data_size, average))
    average2 = rows['number of dummy values'].astype(float).mean(axis=0)
    list2.append((data_size, average2 / average * 100))
new_df = pd.DataFrame(list)
new_df.to_csv(PATH + SUBFOLDER + "dataSizeVsSizeIndexInBytes-" + str(index) + ".csv", header=False, index=False)
new_df2 = pd.DataFrame(list2)
new_df2.to_csv(PATH + SUBFOLDER + "dataSizeVsPercentagePaddingInBytes-" + str(index) + ".csv", header=False, index=False)


# response size (entries) and percentage padding
df = pd.read_csv(PATH + "searchPadding-" + str(index) + ".csv")
df = df[df['emm'] != 'emm']
data_sizes = df['data size'].unique()
list = []
list2 = []
for data_size in data_sizes:
    rows = df.loc[df['data size'] == data_size]
    average = rows['size of response'].astype(float).mean(axis=0)
    list.append((data_size, average))
    average2 = rows['number of dummy values'].astype(float).mean(axis=0)
    list2.append((data_size, average2 / average * 100))
new_df = pd.DataFrame(list)
new_df.to_csv(PATH + SUBFOLDER + "responseSize-" + str(index) + ".csv", header=False, index=False)
new_df2 = pd.DataFrame(list2)
new_df2.to_csv(PATH + SUBFOLDER + "responsePercentagePaddingInBytes-" + str(index) + ".csv", header=False, index=False)
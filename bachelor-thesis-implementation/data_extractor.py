import pandas as pd

PATH = "src/test/resources/data/" 
indices = [0]

# data size vs. time
methods = ["buildIndex", "trapdoor", "search"]
for method in methods:
    for index in indices:
        df = pd.read_csv(PATH + method +"-" + str(index) + ".csv")
        data_sizes = df['data size'].unique()
        list = []
        for data_size in data_sizes:
            rows = df.loc[df['data size'] == data_size]
            average = rows['time [ns]'].mean(axis=0)
            list.append((data_size, average))
        new_df = pd.DataFrame(list)
        new_df.to_csv(PATH + method + "-" + str(index) + "-dataSizeVsTime.csv", header=False, index=False)


# encrypted index size (bytes) and percentage padding
df = pd.read_csv(PATH + "overheadEncryptedIndex-" + str(index) + ".csv")
data_sizes = df['data size'].unique()
list = []
list2 = []
for data_size in data_sizes:
    rows = df.loc[df['data size'] == data_size]
    average = rows['size encrypted index'].mean(axis=0)
    list.append((data_size, average))
    average2 = rows['number of dummy values'].mean(axis=0)
    list2.append((data_size, average2 / average * 100))
new_df = pd.DataFrame(list)
new_df.to_csv(PATH + "dataSizeVsSizeIndexInBytes-" + str(index) + ".csv", header=False, index=False)
new_df2 = pd.DataFrame(list2)
new_df2.to_csv(PATH + "dataSizeVsPercentagePaddingInBytes-" + str(index) + ".csv", header=False, index=False)


# response size (entries) and percentage padding
df = pd.read_csv(PATH + "searchPadding-" + str(index) + ".csv")
data_sizes = df['data size'].unique()
list = []
list2 = []
for data_size in data_sizes:
    rows = df.loc[df['data size'] == data_size]
    average = rows['size of response'].mean(axis=0)
    list.append((data_size, average))
    average2 = rows['number of dummy values'].mean(axis=0)
    list2.append((data_size, average2 / average * 100))
new_df = pd.DataFrame(list)
new_df.to_csv(PATH + "responseSize-" + str(index) + ".csv", header=False, index=False)
new_df2 = pd.DataFrame(list2)
new_df2.to_csv(PATH + "responsePercentagePaddingInBytes-" + str(index) + ".csv", header=False, index=False)
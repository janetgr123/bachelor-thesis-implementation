import pandas as pd
from os.path import exists

PATH = "src/test/resources/data/" 
SUBFOLDER = "dataForPlots/" 
indices = [43,47]
interactive = 1

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
            if method == 'buildIndex':
                for data_size in data_sizes:
                    rows = df.loc[df['data size'] == data_size]
                    average = rows['time [ns]'].astype(float).mean(axis=0)
                    list.append((data_size, average))
            else:
                data_size = data_sizes[-1]
                rows = df.loc[df['data size'] == data_size]
                ranges = rows['range size'].unique()
                for range_size in ranges:
                    rows2 = rows.loc[rows['range size'] == range_size]
                    average = rows2['time [ns]'].astype(float).mean(axis=0)
                    list.append((range_size, average))
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
        file = PATH + "searchPadding-" + str(index) + ".csv"
        if interactive == 1:
            file = PATH + "searchPadding2-" + str(index) + ".csv"
        df = pd.read_csv(file)
        df = df[df['emm'] != 'emm']
        data_sizes = df['data size'].unique()
        data_size = data_sizes[-1]
        rows_data = df.loc[df['data size'] == data_size]
        range_sizes = rows_data['from'].unique() # result printer headers are wrong!
        list = []
        list2 = []
        for range_size in range_sizes:
            rows = rows_data.loc[rows_data['from'] == range_size]
            average = rows['range size'].astype(float).mean(axis=0)
            list.append((range_size, average))
            if average < 0.00001:
                average2 = 0
                list2.append((range_size, average2))
            else:
                average2 = rows['size of response'].astype(float).mean(axis=0)
                list2.append((range_size, average2 / average * 100))
        new_df = pd.DataFrame(list)
        new_df.to_csv(PATH + SUBFOLDER + "responseSize-" + str(index) + ".csv", header=False, index=False)
        new_df2 = pd.DataFrame(list2)
        new_df2.to_csv(PATH + SUBFOLDER + "responsePercentagePaddingInEntries-" + str(index) + ".csv", header=False, index=False)
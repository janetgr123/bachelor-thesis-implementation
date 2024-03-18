import pandas as pd
from os.path import exists

PATH = "src/test/resources/data2/" 
SUBFOLDER = "dataForPlots/" 
indices = [34]
interactive = 0

# response size (entries) and percentage padding
for index in indices:
    file = PATH + "searchPadding-" + str(index) + ".csv"
    if interactive == 1:
        file = PATH + "searchPadding2-" + str(index) + ".csv"
    df = pd.read_csv(file)
    df = df[df['emm'] != 'emm']
    emm = df['emm'].iloc[0]
    data_sizes = df['data size'].unique()
    data_size = data_sizes[-1]
    rows_data = df.loc[df['data size'] == data_size]
    range_sizes = rows_data['range size'].unique() 
    list = []
    list2 = []
    for range_size in range_sizes:
        rows = rows_data.loc[rows_data['range size'] == range_size]
        average = rows['size of response'].astype(float).mean(axis=0)
        list.append((range_size, average))
        if average < 0.00001:
            average2 = 0
            list2.append((range_size, average2))
        else:
            average2 = rows['number of dummy values'].astype(float).mean(axis=0)
            list2.append((range_size, average2 / average * 100))
    new_df = pd.DataFrame(list)
    new_df.to_csv(PATH + SUBFOLDER + "responseSize-" + str(index) + ".csv", header=False, index=False)
    new_df2 = pd.DataFrame(list2)
    new_df2.to_csv(PATH + SUBFOLDER + "responsePercentagePaddingInEntries-" + str(index) + ".csv", header=False, index=False)
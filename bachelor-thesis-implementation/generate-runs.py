

file = open('run-benchmarks-4.txt', 'w')
file.write("# number of emm (0 = basic, 1 = vh, 2 = vho, 3 = non-interactive dp, 4 = non-interactive dp2), \n")
file.write("# isTwoRound, \n")
file.write("# dataset (0 = cali, 1 = spitz, 2 = gowalla), \n")
file.write("# epsilon (default: 0.2),\n")
file.write("# truncation probability (default: 32),\n")
file.write("# k (file index),\n")
file.write("# par (0 = seq, 1 = par),\n")
file.write("# bq (0 = no blocked queries, 1 = blocked queries)\n")
file.write("# wq (0 = no wrap around queries, 1 = wrap around queries)\n")
file.write("# error for bq\n \n")

emms = [0,2]#,3,4]
datasets = [0,1,2]
epsilon = [0.2, 0.4]
truncation = [32]
twoRounds = [1]
bqwq = ["10","01"]
par = [1]
error = 16

TASK = "taskset -c "
STRING = "mvn test-compile exec:java -Dexec.mainClass=ch.bt.benchmark.BenchmarkRunner -Dexec.classpathScope=test -Dexec.arguments="

k = 144
"""
for dataset in datasets:
    for t in truncation:
        for eps in epsilon:
            s = ""
            s += str(0) + "," 
            s += str(0) + "," 
            s += str(dataset) + "," 
            s += str(eps) + "," 
            s += str(t) + "," 
            s += str(k) + "," 
            s += str(0) + ","
            s += str(0) + "," 
            s += str(0) + "," 
            s += str(0) + "\n"
            file.write(TASK + str(k % 32) + "-" + str((k + 3) % 32) + "," + str(56 + (k % 32)) + "-" + str(56 + ((k + 3) % 32)) + " " + STRING + s)
            k = k + 4

for dataset in datasets:
    for t in truncation:
        for eps in epsilon:
            for p in par:
                for round in twoRounds:
                    s = ""
                    s += str(0) + "," 
                    s += str(round) + "," 
                    s += str(dataset) + "," 
                    s += str(eps) + "," 
                    s += str(t) + "," 
                    s += str(k) + "," 
                    s += str(p) + ","
                    s += str(0) + "," 
                    s += str(0) + "," 
                    s += str(0) + "\n"
                    file.write(TASK + str(k % 32) + "-" + str((k + 3) % 32) + "," + str(56 + (k % 32)) + "-" + str(56 + ((k + 3) % 32)) + " " + STRING + s)
                    k = k + 4

for dataset in datasets:
    for t in truncation:
        for eps in epsilon:
            for emm in emms:
                s = ""
                s += str(emm) + "," 
                s += str(0) + "," 
                s += str(dataset) + "," 
                s += str(eps) + "," 
                s += str(t) + "," 
                s += str(k) + "," 
                s += str(0) + ","
                s += str(0) + "," 
                s += str(0) + "," 
                s += str(0) + "\n"
                file.write(TASK + str(k % 32) + "-" + str((k + 3) % 32) + "," + str(56 + (k % 32)) + "-" + str(56 + ((k + 3) % 32)) + " " + STRING + s)
                k = k + 4
"""
                
for dataset in datasets:
    for t in truncation:
        for eps in epsilon:
            for emm in emms:
                s = ""
                s += str(emm) + "," 
                s += str(0) + "," 
                s += str(dataset) + "," 
                s += str(eps) + "," 
                s += str(t) + "," 
                s += str(k) + "," 
                s += str(1) + ","
                s += str(0) + "," 
                s += str(0) + "," 
                s += str(0) + "\n"
                file.write(TASK + str(k % 32) + "-" + str((k + 3) % 32) + "," + str(56 + (k % 32)) + "-" + str(56 + ((k + 3) % 32)) + " " + STRING + s)
                k = k + 4

for dataset in datasets:
    for t in truncation:
        for eps in epsilon:
            for p in par:
                for round in twoRounds:
                    s = ""
                    s += str(0) + "," 
                    s += str(round) + "," 
                    s += str(dataset) + "," 
                    s += str(eps) + "," 
                    s += str(t) + "," 
                    s += str(k) + "," 
                    s += str(p) + ","
                    s += str(0) + "," 
                    s += str(0) + "," 
                    s += str(0) + "\n"
                    file.write(TASK + str(k % 32) + "-" + str((k + 3) % 32) + "," + str(56 + (k % 32)) + "-" + str(56 + ((k + 3) % 32)) + " " + STRING + s)
                    k = k + 4

for dataset in datasets:
    for t in truncation:
        for eps in epsilon:
            for emm in emms:
                for b in bqwq:
                    s = ""
                    s += str(emm) + "," 
                    s += str(0) + "," 
                    s += str(dataset) + "," 
                    s += str(eps) + "," 
                    s += str(t) + "," 
                    s += str(k) + "," 
                    s += str(0) + ","
                    if (b == "10"):
                        s += str(1) + "," 
                        s += str(0) + ","
                        s += str(error) + "\n"
                    elif (b == "01"):
                        s += str(0) + "," 
                        s += str(1) + ","
                        s += str(0) + "\n"
                    file.write(TASK + str(k % 32) + "-" + str((k + 3) % 32) + "," + str(56 + (k % 32)) + "-" + str(56 + ((k + 3) % 32)) + " " + STRING + s)
                    k = k + 4
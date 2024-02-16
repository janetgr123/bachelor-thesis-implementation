import matplotlib.pyplot as plt
import numpy as np

x = np.linspace(0, 1, 100)
x = x[10:] # remove 0
y = 27.7 / x 
plt.plot(x, y, color='black', linestyle='solid', linewidth=0.5)
plt.ylabel('$\ell^*(\lambda)$')
plt.xlabel('$\epsilon$')
plt.grid()
plt.savefig("corrfactor.pdf")
plt.close()
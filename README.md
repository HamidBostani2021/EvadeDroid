# EvadeDroid
This is a tool for generating Android adversarial examples in a black-box setting. The source code is currently being prepared to be open-sourced. We will gradually push it into the repository as it is ready.

## Installation
1. Install Python 3 (>= 3.6) in your machine, which can be either Windows or Linux. Note for using Windows machine, in some modules, the following codes that are related to parallelizing should be cut. 

```python
import torch
mp = torch.multiprocessing.get_context('forkserver')

\...

with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(..., zip(...)))

```

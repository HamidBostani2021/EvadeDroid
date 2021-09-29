# EvadeDroid
This is a tool for generating Android adversarial examples in a black-box setting. EvadeDroid's pipeline use a two-step approach:

1. Preparation that is responsible for preparing an action set including a collection of gadgets (i.e., entry point, organ, and vein) extracted from benign Android apps that are publicly accessible. 

2. Manipulation that is in charge of perturbing malware samples by applying a sequence of transformations gathered in the action set into malware samples over several iterations.

The source code is currently being prepared to be open-sourced. We will gradually push it into the repository as it is ready.

## Installation
1. Install Python 3 (>= 3.6) in your machine, which can be either Windows or Linux. Note for working with a Windows machine, you have to cut the following codes that are related to parallelizing processes in Python. These codes are used in different modules (e.g., main_pipeline.py). 

```python
import torch
mp = torch.multiprocessing.get_context('forkserver')

with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(..., zip(...)))

```

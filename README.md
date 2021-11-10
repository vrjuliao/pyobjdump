# PyObjdump

It is a simple dump for ELF files written in python3.\
Author: Vinicius Julião Ramos\
[Personal Page](https://vrjuliao.github.io)

### Requirements:
- capstone-engine (`pip3 install capstone`)
- pyelftools (`pip3 install pyelftools`)

### Execution
After install the required libraries, type:
```sh
python3 diff.py prog1 prog2
```

## Additional question: "can you identify what has been modified/patched and why?"
Answer:\
Yes, despite only one function was modified, given the name of that function we
can imagine what has been modified.
In the given example, the only different function is `ap_normalize_path`, in which
I suppose that is a function that receives a string and rewrite it for a normalize
version, that some other part of that system demands.
Since there are 21 possible branches paths (Loops or conditional calls) between
those two binary files, it is possible to infer `prog2` as a more precise
version of that path normalization.

Afer a superficial reading of the methods names and the graph representation
of the branches between functions and loops, we can see that those binary files
have a http service.
Probably, this function (`ap_normalize_path`) was improved to fix the requested
links.

## Short description
Despite the given binaries files are too similar each other, this following
solution have more capabilities than was expected.
Here we have the list of capabilities of this system:
- Identify function that just one binary contains
- Identify how many calls a function do to other one and compare it against
  another binary.
  In other words, if in the prog1 the function A calls C 3 times and in prog 2
  A calls C 2 times, it is displayed at the stdout.
- Shows the following information for each function:
  - number of instructions
  - number of memory access
  - number of possible branches:
    function calls, loops and conditional flow management (if-else and switch-case).
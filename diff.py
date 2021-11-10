import sys
from objdump import Objdump
from diffObjdump import DiffObjdump

dmp1 = Objdump(sys.argv[1])
dmp2 = Objdump(sys.argv[2])
diff = DiffObjdump(dmp1, dmp2)
diff.diff_report()
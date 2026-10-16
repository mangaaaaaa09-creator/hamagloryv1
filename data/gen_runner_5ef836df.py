
import sys, os
sys.path.insert(0, r"/storage/emulated/0/Download/GLORY")
os.chdir(r"/storage/emulated/0/Download/GLORY")
import gen
gen.run_generation(region="ME", prefix="hello__", count=4)

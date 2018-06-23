# Monotonic Counter with Intel SGX and Java
## Before run in every server node execute these commands:
```
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`pwd`
source /opt/intel/sgxsdk/environment
```

## For compiling Encalve execute:
```
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`pwd`
source /opt/intel/sgxsdk/environment
make clean && make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
java JavaApp
```

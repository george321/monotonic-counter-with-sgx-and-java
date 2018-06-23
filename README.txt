export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`pwd`
source /opt/intel/sgxsdk/environment
make clean && make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
java JavaApp


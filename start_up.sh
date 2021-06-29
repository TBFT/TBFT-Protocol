#! /bin/sh
cd ~/minbft-go
source /opt/intel/sgxsdk/environment
sudo bash -c "echo /opt/intel/sgxsdk/sdk_libs > /etc/ld.so.conf.d/sgx-sdk.conf"
sudo ldconfig
export SGX_MODE=SIM
make install
export LD_LIBRARY_PATH="${PWD}/sample/lib:${LD_LIBRARY_PATH}"
cd sample
bin/keytool generate -u lib/libusig.signed.so
cp config/consensus.yaml ./
cp peer/peer.yaml ./
bin/peer run 0 &
bin/peer run 1 &
bin/peer run 2 &

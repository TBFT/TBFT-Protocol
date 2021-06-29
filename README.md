# TBFT

  * [Overview](#Overview)
  * [Requirements](#requirements)
      * [Operating System](#operating-system)
      * [Golang](#golang)
      * [Intel® SGX SDK](#intel-sgx-sdk)
  * [Getting Started](#getting-started)
      * [Building](#building)
      * [Running Example](#running-example)
      * [Code Structure](#code-structure)
  * [Status](#Status)
  * [License](#license)
  * [Acknowledgement](#Acknowledgement)

## Overview

This repository is an implementation of TBFT, an understandable and efficient Byzantine Fault Tolerance(BFT) protocol using trusted execution environment(TEE). 

## Requirements ##

### Operating System ###

The project has been tested on Ubuntu 18.04. 
Additional required packages can be installed as follows:

```sh
sudo apt-get install build-essential pkg-config
```

### Golang ###

Go 1.15 or later is required to build this project. For installation instructions please visit
[this page](https://golang.org/doc/install).

### Intel® SGX SDK ###

The Intel® SGX enclave implementation has been tested with Intel® SGX
SDK for Linux version 2.9.1. For installation instuctions please visit
[download page][sgx-downloads].
Please note that Intel SGX has two operation modes and required software
components depend on operation mode.

 - If you run in HW mode, you have to install all three components:
   SGX driver, PSW, and SGX SDK.
 - If you run in simulation mode, only SGX SDK is required.

A conventional directory to install
the SDK is `/opt/intel/`. Please do not forget to source
`/opt/intel/sgxsdk/environment` file in your shell. Alternatively, one
can add the following line to `~/.profile`:

```sh
. /opt/intel/sgxsdk/environment
```

If you run in simlation mode, you need create/update the link to
the additional directory of shared libraries with following commands:

```
sudo bash -c "echo /opt/intel/sgxsdk/sdk_libs > /etc/ld.so.conf.d/sgx-sdk.conf"
sudo ldconfig
```

When using a machine with no SGX support, only SGX simulation mode is
supported. In that case, please be sure to export the following
environment variable, e.g. by modifying `~/.profile` file:

```sh
export SGX_MODE=SIM
```

[sgx-downloads]: https://01.org/intel-software-guard-extensions/downloads

## Getting Started ##

All following commands are supposed to be run in the root of the
module's source tree.

### Building ###

The project can be build by issuing the following command. At the
moment, the binaries are installed in `sample/bin/` directory; no root
privileges are needed.

```sh
make install
```

### Running Example ###

Running the example requires some set up. Please make sure the project
has been successfully built and `sample/bin/keytool` and
`sample/bin/peer` binaries were produced. Those binaries can be
supplied with options through a configuration file, environment
variables, or command-line arguments. More information about available
options can be queried by invoking those binaries with `help`
argument. Sample configuration files can be found in
`sample/authentication/keytool/` and `sample/peer/` directories
respectively.

Before running the example, the environment variable `$LD_LIBRARY_PATH`
needs to include `sample/lib` where `libusig_shim.so` is installed by
`make install`.

```sh
export LD_LIBRARY_PATH="${PWD}/sample/lib:${LD_LIBRARY_PATH}"
```

#### Generating Keys ####

The following command are to be run from `sample` directory.

```sh
cd sample
```

Sample key set file for testing can be generate by using `keytool`
command. This command produces a key set file suitable for running the
example on a local machine:

```sh
bin/keytool generate -u lib/libusig.signed.so
```

This invocation will create a sample key set file named `keys.yaml`
containing 3 key pairs for replicas and 1 key pair for a client by
default.

#### Consensus Options Configuration ####

Consensus options can be set up by means of a configuration file. A
sample consensus configuration file can be used as an example:

```sh
cp config/consensus.yaml ./
```

#### Peer Configuration ####

Peer configuration can be supplied in a configuration file. Selected
options can be modified through command line arguments of `peer`
binary. A sample configuration can be used as an example:

```sh
cp peer/peer.yaml ./
```

For more configuration information, please see Config.md. 

#### Running Replicas ####

To start up an example consensus network of replicas on a local
machine, invoke the following commands:

```sh
bin/peer run 0 &
bin/peer run 1 &
bin/peer run 2 &
```

This will start the replica nodes as 3 separate OS processes in background using the configuration files prepared in previous steps. There seems to be some concurrency bugs in the codebase we use. We did not try to solve these bugs because the codebase is large and changeable. If these bugs occur, you only need to run it again. 

#### Submitting Requests ####

Requests can be submitted for ordering and execution to the example
consensus network using the same `peer` binary and configuration files
for convenience. It is better to issue the following commands in
another terminal so that the output messages do not intermix:

```sh
bin/peer request "First request" "Second request" "Another request"
```

This command should produce the following output showing the result
of ordering and execution of the submitted requests:

```
Reply: {"Height":1,"PrevBlockHash":null,"Payload":"Rmlyc3QgcmVxdWVzdA=="}
Reply: {"Height":2,"PrevBlockHash":"DuAGbE1hVQCvgi+R0E5zWaKSlVYFEo3CjlRj9Eik5h4=","Payload":"U2Vjb25kIHJlcXVlc3Q="}
Reply: {"Height":3,"PrevBlockHash":"963Kn659GbtX35MZYzguEwSH1UvF2cRYo6lNpIyuCUE=","Payload":"QW5vdGhlciByZXF1ZXN0"}
```

The output shows the submitted requests being ordered and executed by
a sample blockchain service. The service executes request by simply
appending a new block for each request to the trivial blockchain
maintained by the service.

#### Tear Down ####

The following command can be used to terminate running replica
processes and release the occupied TCP ports:

```sh
killall peer
```

### Code Structure ###

The code divided into core consensus protocol implementation and
sample implementation of external components required to interact with
the core. The following directories contain the code:

  * `api/` - definition of API between core and external components
  * `client/` - implementation of client-side part of the protocol
  * `core/` - implementation of core consensus protocol.
  * `usig/` - implementation of SGX Enclave, tamper-proof component
  * `messages/` - definition of the protocol messages. We add a new message type called Vote.
  * `sample/` - sample implementation of external interfaces
    * `authentication/` - generation and verification of
                          authentication tags
      * `keytool/` - tool to generate sample key set file
    * `conn/` - network connectivity
    * `config/` - consensus configuration provider
    * `requestconsumer/` - service executing ordered requests
    * `peer/` - CLI application to run a replica/client instance

## Status ##

This project is in experimental development stage. It is **not** suitable for any kind of production use. Due to the limited time, we did not try to deal with all situations. But please note that these simplifications have no essential effect on the experimental results. In the future, we plan to improve this implementation. 

## License ##

Source code files are licensed under the [Apache License, Version 2.0](LICENSE).

Documentation files are licensed under the [Creative Commons Attribution 4.0 International License][cc-40].

[cc-40]: http://creativecommons.org/licenses/by/4.0/

## Acknowledgement

This project is based on an open-source repository, [MinBFT](https://github.com/hyperledger-labs/minbft). Thanks for their helpful codebase!
ADSC-SNARK Applications and Benchmarking
================================================================================

This repository contains demo applications for ADSC-SNARK. It also provides
an implementation of a folklore ADSC-SNARK, which arithmetizes signature
verification and collision resistant hash functions in the relation. 

The ADSC-SNARK by Reinhart et. al and corresponding benchmarking routines
are implemented in the libsnark submodule

--------------------------------------------------------------------------------
Build instructions
--------------------------------------------------------------------------------

These build instructions have been tested on Ubuntu 20.04 and Debian 10

1. Install build tools and dependencies

```
sudo apt-get install build-essential cmake libgmp3-dev libssl-dev pkg-config libboost-all-dev
```

2. Clone submodules

```
git submodule init && git submodule update
```

3. Configure

```
mkdir build && cd build
cmake ..  
```
BN254 will be used as the default elliptic curve.
For other elliptic curves, add -DCURVE=<CURVE> in the configure step and replace <CURVE> with any of:
- BN254
- BN183
- BN124
- GMV181
- GMV97
- GMV58

Example:

```
cmake -DCURVE=BN183 ..
```

4. Build

Demo Application: 3 DOF PID Controller

```
cmake --build . --target controller_scenario -j 8
```

Profiling Applications for ADSC-SNARKs

```
cmake --build . --target profile_folklore_adscsnark profile_r1cs_gg_ppzkadscsnark profile_r1cs_ppzkadsnark profile_sc_lego_gro16 -j 8
```

--------------------------------------------------------------------------------
Run instructions
--------------------------------------------------------------------------------

Demo Application: 3 DOF PID Controller

```
./application/controller_scenario --generator --sensor --device --verifier --file --rounds 10
```

The --file option lets the parties communicate via disc, otherwise communication is in RAM

Profiling Applications:
Profile ADSC-SNARKs for 2^1 - 2^4 inputs and 2^1 - 2^4 states
```
./adscsnark-folklore/profile_folklore_adscsnark --profile -i 1 4 -s 1 4
./depends/libsnark/libsnark/profile_r1cs_gg_ppzkadscsnark --profile -i 1 4 -s 1 4
./depends/libsnark/libsnark/profile_r1cs_ppzkadsnark --profile -i 1 4
./depends/libsnark/libsnark/profile_sc_lego_gro16 --profile -s 1 4
```
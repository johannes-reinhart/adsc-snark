ADSC-SNARK Applications and Benchmarking
================================================================================

This repository contains demo applications for ADSC-SNARK. It also provides
an implementation of a strawman ADSC-SNARK, which arithmetizes signature
verification and collision resistant hash functions in the relation. 

The ADSC-SNARK and corresponding benchmarking routines
are implemented in the libsnark submodule

The following instructions have been tested on **Ubuntu 24.04**

--------------------------------------------------------------------------------
Build instructions
--------------------------------------------------------------------------------

0. Install build tools and dependencies

```
sudo apt-get install build-essential cmake libgmp3-dev libssl-dev pkg-config libboost-all-dev
```

1. Clone submodules

```
git submodule init && git submodule update
```

2. Configure

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

3. Build

Demo Application: 3 DOF PID Controller

```
cmake --build . --target controller_scenario -j 8
```

Profiling Applications for ADSC-SNARKs

```
cmake --build . --target profile_strawman_adscsnark profile_r1cs_gg_ppzkadscsnark profile_r1cs_ppzkadsnark profile_sc_lego_gro16 -j 8
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

- **profile_strawman_adscsnark**: ADSC-SNARK with arithmetized hash function and signature verification
- **profile_r1cs_gg_ppzkadscsnark**: The ADSC-SNARK by Reinhart et al. (CCS'25)
- **profile_r1cs_ppzkadsnark**: The AD-SNARK by Backes et al. (S&P'15)
- **profile_r1cs_gg_ppzkadscsnark**: An SC-SNARK by functional composition of LegoGro16, Campanelli et al.  (CCS'19)
```
./adscsnark-strawman/profile_strawman_adscsnark --profile -i 1 4 -s 1 4
./depends/libsnark/libsnark/profile_r1cs_gg_ppzkadscsnark --profile -i 1 4 -s 1 4
./depends/libsnark/libsnark/profile_r1cs_ppzkadsnark --profile -i 1 4
./depends/libsnark/libsnark/profile_sc_lego_gro16 --profile -s 1 4
```

--------------------------------------------------------------------------------
Troubleshooting
--------------------------------------------------------------------------------

For large inputs, AD-SNARK by Backes et. al. (profile_r1cs_ppzkadsnark) requires 
a lot of stack memory. If the OS reports memory violations, try to increase
the stack size before launching the binary:

```
ulimit -s unlimited
```
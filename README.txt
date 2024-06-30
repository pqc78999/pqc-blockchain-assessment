# PQS-BC: Comparative Analysis of NIST Post-Quantum Signatures for Blockchain
This project benchmarks 40 NIST Additional Round 1 Candidates and 3 selected Candidates, focusing on their application in blockchain technology.

## Contents of This Folder
- **PQCgenKAT_sign.c**: Modified from the original NIST version to include execution time measurement and CSV output.
- **CopyPQC.sh**: Script to replace the original PQCgenKAT_sign.c in each algorithm's Params Folder.
- **compile.sh**: Compiles PQCgenKAT_sign.c in each algorithm's Params Folder.
- **execution.sh**: Executes PQCgenKAT_sign in each algorithm's Params Folder.
- **execution_main.sh**: Executes `execution.sh` across all Algorithm Folders.
- **TestingResults.xlsx**: Contains testing data from a system with an Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 64-bit OS, and x64-based processor.
- **ResultTables.xlsx**: Analyzed results with rankings for blockchain recommendations.
- **README.txt**: This document.

## How to Use
1. Download the latest packages from [NIST's PQC Digital Signatures Round 1 Additional Signatures](https://csrc.nist.gov/Projects/pqc-dig-sig/round-1-additional-signatures).
2. Place `CopyPQC.sh`, `compile.sh`, `execution.sh`, and `PQCgenKAT_sign.c` into each implementation folder you wish to test.
3. Verify successful compilation and execution with the modified `PQCgenKAT_sign.c`. Custom modifications may be required for some implementations.
4. Repeat steps 2-3 for all target schemes.
5. Use `execution_main.sh` to automatically execute all targets simultaneously, ensuring fairness.

## Notes
- The provided scripts are tested on Ubuntu 22.04.3 LTS.
- Due to varying coding styles among submissions, the default script and `PQCgenKAT_sign.c` may require modifications for some implementations.
- Libraries for CROSS and LESS functionalities are sourced from the XKCP project on GitHub: https://github.com/XKCP/XKCP.git.
#!/bin/bash
make
echo 'Run P2PKH script'
./Decompiler 76a914ba507bae8f1643d2556000ca26b9301b9069dc6b88ac
echo 'Run P2PK script'
./Decompiler 4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac
echo 'Run P2SH script'
./Decompiler a9146e8ea702743a672edf2ee1d0c21737faf2b2aa8487
echo 'Run P2WPKH script'
./Decompiler 00149d57c57c3573b58db6b50c10651fc23e40eac0a1
echo 'Run P2WSH script' # Ad the following link https://blockstream.info/address/bc1qu4ekhuffwmx8zzucxw4v9cen8fd9a8ey4jruuj0gdz6fddggvq3s4g6esd
./Decompiler 0020e5736bf12976cc710b9833aac2e3333a5a5e9f24ac87ce49e868b496b5086023

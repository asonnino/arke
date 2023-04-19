# ARKE Cryptographic Library

This workspace contains all the necessary cryptography to run the ARKE system.

The code is organised as follows:
- `arke_core` contains the core cryptographic components of ARKE: a identity-based non-interactive key exchange (ID-NIKE) and the unlinkable handshake.
- `hash_functions` contains useful cryptographic hash functions and importantly functions to "hash-to-curves" G1 and G2.
- `secret_sharing` is a naive implementation of Shamir secret sharing.

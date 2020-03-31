# PowerHash
Module to hash (checksum) files and Bytearrays  to compare files, check integrity and find duplicates

This is currently in beta / Testing stage!
Tested with PowerShell 5.1 and 7.

This Module is using the cryptographic classes out of the .NET Framework AND the [non-cryptographic hash functions](http://en.wikipedia.org/wiki/List_of_hash_functions#Non-cryptographic_hash_functions) out of the following C# Project
https://github.com/brandondahler/Data.HashFunction

Currently there is only one Function in this Module to checksum Files.

- Get-PwFileHash

## Why not using the build in PowerShell cmdlet Get-FileHash ?

To find duplicate Files or to do Integrity checks after a copy (backup) of data files, there is no need for Cryptographic secure hash functions.
The only need for the result of a hash function here is collision-resistance and Speed.
So this Module offers non-cryptographic hash functions to archive this.

Get-PwFileHash offers the same Cryptographic secure hash functions like the build in Get-FileHash cmdlet, plus the (faster) non cryptographic hash functions.

**Use hashes with care!**
In computer science, a collision is a situation that occurs when two distinct pieces of data have the same hash value, checksum, fingerprint, or cryptographic digest.
**Every hash function with more inputs than outputs will necessarily have collisions.**
See: https://en.wikipedia.org/wiki/Collision_resistance

## Cryptographic and Non-Cryptographic Hash Functions
       
A cryptographic hash function aims to guarantee a number of security properties.
Most importantly that it's hard to find collisions or pre-images and that the output appears random.
(There are a few more properties, and "hard" has well defined bounds in this context, but that's not important here.)

Non cryptographic hash functions just try to avoid collisions for non malicious input.
Some aim to detect accidental changes in data (CRCs), others try to put objects into different buckets in a hash table with as few collisions as possible.

In exchange for weaker guarantees they are typically (much) faster.
        
See also: https://dadario.com.br/cryptographic-and-non-cryptographic-hash-functions/

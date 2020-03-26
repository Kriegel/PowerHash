# PowerHash
Module to hash (checksum) files and Bytearrays  to compare files, check integrity and find duplicates

This is currently in beta / Testing stage!
Tested with PowerShell 5.1 and 7.

This Module is using the cryptographic classes out of the .NET Framework AND the [non-cryptographic hash functions](http://en.wikipedia.org/wiki/List_of_hash_functions#Non-cryptographic_hash_functions) out of the following C# Project
https://github.com/brandondahler/Data.HashFunction

Currently there is only one Function in this Module to checksum Files.

- Get-PwFileHash

I recommend to use xxHash (32 or 64) for VERY Fast checksums
https://github.com/Cyan4973/xxHash

## Cryptographic and Non-Cryptographic Hash Functions
       
A cryptographic hash function aims to guarantee a number of security properties.
Most importantly that it's hard to find collisions or pre-images and that the output appears random.
(There are a few more properties, and "hard" has well defined bounds in this context, but that's not important here.)
Non cryptographic hash functions just try to avoid collisions for non malicious input.
Some aim to detect accidental changes in data (CRCs), others try to put objects into different buckets in a hash table with as few collisions as possible.

In exchange for weaker guarantees they are typically (much) faster.
        
See also: https://dadario.com.br/cryptographic-and-non-cryptographic-hash-functions/

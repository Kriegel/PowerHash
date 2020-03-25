# PowerHash
Module to hash (checksum) files and Bytearrays  to compare files, check integrity and find duplicates

This is currently in beta / Testing stage!
Tested with PowerShell 5.1 and 7.

This Module is using the cryptographic classes out of the .NET Framework AND the [non-cryptographic hash functions](http://en.wikipedia.org/wiki/List_of_hash_functions#Non-cryptographic_hash_functions) out of the following C# Project
https://github.com/brandondahler/Data.HashFunction

I recommend to use xxHash (32 or 64) for VERY Fast checksums
https://github.com/Cyan4973/xxHash

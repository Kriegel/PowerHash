<#
.SYNOPSIS
        Computes the hash (checksum) value for a file by using a specified hash algorithm.

.DESCRIPTION
        The `Get-PwFileHash` cmdlet computes the hash value for a file by using a specified hash algorithm.
        A hash value is a unique value that corresponds to the content of the file.
        Rather than identifying the contents of a file by its file name, extension, or other designation, a hash can assign a unique value to the contents of a file.
        File names and extensions can be changed without altering the content of the file, and without changing the hash value.
        Similarly, the file's content can be changed without changing the name or extension.
        However, changing even a single character in the contents of a file changes the hash value of the file.

        The purpose of hash values is to provide a cryptographically-secure way to verify that the contents of a file have not been changed. While some hash algorithms,
        including MD5 and SHA1, are no longer considered secure against attack, the goal of a secure hash algorithm is to render it impossible to change the contents of a file --
        either by accident, or by malicious or unauthorized attempt -- and maintain the same hash value.
        You can also use hash values to determine if two different files have exactly the same content.
        If the hash values of two files are identical, the contents of the files are also identical.

        By default, the `Get-PwFileHash` cmdlet uses the SHA256 algorithm, although any hash algorithm that is supported by the target operating system can be used.
        
        Get-PwFileHash supports also non-cryptographic hash functions and provide implementations of public hash functions.

        
        Cryptographic and Non-Cryptographic Hash Functions
        --------------------------------------------------
        See also: https://dadario.com.br/cryptographic-and-non-cryptographic-hash-functions/

        
        A cryptographic hash function aims to guarantee a number of security properties.
        Most importantly that it's hard to find collisions or pre-images and that the output appears random.
        (There are a few more properties, and "hard" has well defined bounds in this context, but that's not important here.)

        Non cryptographic hash functions just try to avoid collisions for non malicious input.
        Some aim to detect accidental changes in data (CRCs), others try to put objects into different buckets in a hash table with as few collisions as possible.

        In exchange for weaker guarantees they are typically (much) faster.
        
        
         


.PARAMETER Algorithm
        
        Specifies the hash function to use for computing the hash value of the contents of the specified file or stream.
        A hash function has the property that it is infeasible to find two different files with the same hash value.
        Hash functions are commonly used with digital signatures and for data integrity.
          
        
        The acceptable values for Cryptographic hashes functions in this parameter are:

        - SHA1
        - SHA256
        - SHA384
        - SHA512
        - MD5
                
        For security reasons, MD5 and SHA1, which are no longer considered secure, should only be used for simple change validation, and should not be used to generate hash values for files that require protection from attack or tampering.
        
        Cryptographic algorithms that are no longer supported by .Net Core are:
        MACTripleDES,RIPEMD160

        The acceptable values for non Cryptographic hashes functions in this parameter are:

        - BernsteinHash
        - Blake2
        - Buzhash
        - CRC
        - ELF64
        - FNV1
        - FNV1a
        - Jenkins1
        - Jenkins2
        - MurmurHash3
        - Pearson
        - SpookyHashV1
        - SpookyHashV2
        - xxHash32
        - xxHash64
        - ModifiedBernsteinHash
        - MetroHash64
        - MetroHash128

        For more information about the non Cryptographic hashes, see: https://github.com/brandondahler/Data.HashFunction
        dropped algorithms which are not supporting io-streaming are:
        CityHash,Jenkins3,MurmurHash1,MurmurHash2


        If no value is specified, or if the parameter is omitted, the default value is SHA256.

.PARAMETER InputStream
        Specifies the input stream.

.PARAMETER LiteralPath
        Specifies the path to a file. Unlike the Path parameter, the value of the LiteralPath parameter is used exactly as it is typed. No characters are interpreted as wildcard characters. If the path includes escape characters, enclose the path in single quotation marks. Single quotation marks instruct PowerShell not to interpret characters as escape sequences.

.PARAMETER Path
        Specifies the path to one or more files as an array. Wildcard characters are permitted.

.EXAMPLE
        Get-PwFileHash /etc/apt/sources.list | Format-List

        Algorithm : SHA256
        Hash      : 3CBCFDDEC145E3382D592266BE193E5BE53443138EE6AB6CA09FF20DF609E268
        Path      : /etc/apt/sources.list

.EXAMPLE
        Get-PwFileHash C:\Users\user1\Downloads\Contoso8_1_ENT.iso -Algorithm SHA384 | Format-List

        Algorithm : SHA384
        Hash      : 20AB1C2EE19FC96A7C66E33917D191A24E3CE9DAC99DB7C786ACCE31E559144FEAFC695C58E508E2EBBC9D3C96F21FA3
        Path      : C:\Users\user1\Downloads\Contoso8_1_ENT.iso

.EXAMPLE
        $wc = [System.Net.WebClient]::new()
        $pkgurl = 'https://github.com/PowerShell/PowerShell/releases/download/v6.2.4/powershell_6.2.4-1.debian.9_amd64.deb'
        $publishedHash = '8E28E54D601F0751922DE24632C1E716B4684876255CF82304A9B19E89A9CCAC'
        $FileHash = Get-PwFileHash -InputStream ($wc.OpenRead($pkgurl))
        $FileHash.Hash -eq $publishedHash

        True

.EXAMPLE
        $stringAsStream = [System.IO.MemoryStream]::new()
        $writer = [System.IO.StreamWriter]::new($stringAsStream)
        $writer.write("Hello world")
        $writer.Flush()
        $stringAsStream.Position = 0
        Get-PwFileHash -InputStream $stringAsStream | Select-Object Hash

        Hash
        ----
        E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855

.INPUTS
        System.String

.OUTPUTS
        Microsoft.Powershell.Utility.FileHash

.LINK
        https://docs.microsoft.com/powershell/module/microsoft.powershell.utility/Get-PwFileHash?view=powershell-7&WT.mc_id=ps-gethelp

.LINK
        Online Version:

.LINK
        Format-List
#>
Function Get-PwFileHash {

    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName='Path', Position = 0)]
        [System.String[]]
        $Path,

        [Parameter(Mandatory, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName = $true)]
        [Alias('PSPath')]
        [System.String[]]
        $LiteralPath,
        
        [Parameter(Mandatory, ParameterSetName='Stream')]
        [System.IO.Stream]
        $InputStream,

        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5','BernsteinHash','Blake2','Buzhash','CRC','ELF64','FNV1','FNV1a','Jenkins1','Jenkins2','MurmurHash3','Pearson','SpookyHashV1','SpookyHashV2','xxHash32','xxHash64','ModifiedBernsteinHash','MetroHash64','MetroHash128')]
        [System.String]
        $Algorithm ='SHA256'
    )
    
    begin
    {
        
        #Write-Host "Trying ${Algorithm}" -ForegroundColor Magenta

        # Construct the strongly-typed crypto object
        
        $AlgorithmFound = $False
        $HashFunctionUsed = $False
        
        # First see if it has a FIPS algorithm  
        $hasherType = "System.Security.Cryptography.${Algorithm}CryptoServiceProvider" -as [Type]
        if ($hasherType)
        {
            $hasher = $hasherType::New()
            $AlgorithmFound = $True
        }
        else
        {
            # Check if the type is supported in the current system
            $algorithmType = "System.Security.Cryptography.${Algorithm}" -as [Type]
            if ($algorithmType)
            {
                if ($Algorithm -eq 'MACTripleDES')
                {
                    $hasher = $algorithmType::New()
                     $AlgorithmFound = $True
                }
                else
                {
                    $hasher = $algorithmType::Create()
                    $AlgorithmFound = $True
                }
            }
        }

        # try to load  brandondahler / Data.HashFunction non-cryptographic hash function from Module Path
        
        $DotNetVersionPathPart = 'net45'
        
        If ($PSVersionTable.PSVersion.Major -gt 5) {
            $DotNetVersionPathPart = 'netstandard1.1'
        }

        if(-Not $AlgorithmFound) {
            Try {
                
                # Algorithm name shim
                
                ${AlgorithmName} = ${Algorithm}
                ${AlgoFactoryName} = ${Algorithm}
                
                switch (${Algorithm})
                {
                    
                    'ModifiedBernsteinHash' { ${AlgorithmName} = 'BernsteinHash' }
                    'Blake2' { ${AlgoFactoryName} = 'Blake2B' }
                    'FNV1' { 
                                ${AlgorithmName} = 'FNV'
                            }
                    'FNV1a' { 
                                ${AlgorithmName} = 'FNV'
                            }
                     'Jenkins1' {
                                    ${AlgorithmName} = 'Jenkins'
                                    ${AlgoFactoryName} = 'JenkinsOneAtATime'
                                }
                     'Jenkins2' {
                                    ${AlgorithmName} = 'Jenkins'
                                    ${AlgoFactoryName} = 'JenkinsLookup2'
                                }
                     'Jenkins3' {
                                    ${AlgorithmName} = 'Jenkins'
                                    ${AlgoFactoryName} = 'JenkinsLookup3'
                                }
                     'MetroHash64'{
                                    ${AlgorithmName} = 'MetroHash'
                                }
                     'MetroHash128'{
                                    ${AlgorithmName} = 'MetroHash'
                                }
                     'MurmurHash1' {
                                    ${AlgorithmName} = 'MurmurHash'
                                }
                     'MurmurHash2' {
                                    ${AlgorithmName} = 'MurmurHash'
                                }
                     'MurmurHash3' {
                                    ${AlgorithmName} = 'MurmurHash'
                                  }

                     'SpookyHashV1' {
                                    ${AlgorithmName} = 'SpookyHash'
                                }
                     'SpookyHashV2' {
                                    ${AlgorithmName} = 'SpookyHash'
                                }
                    'xxHash32' {
                                    ${AlgorithmName} = 'xxHash'
                                    ${AlgoFactoryName} = 'xxHash'
                                }
                    'xxHash64' {
                                    ${AlgorithmName} = 'xxHash'
                                    ${AlgoFactoryName} = 'xxHash'
                                    $xxHashConfig = [OpenSource.Data.HashFunction.xxHash.xxHashConfig]::new()
                                    $xxHashConfig.HashSizeInBits = 64
                                }
                }

                Write-Verbose "Loading algorithm: $PSScriptRoot\..\OpenSource.Data.HashFunction\$DotNetVersionPathPart\OpenSource.Data.HashFunction.${AlgorithmName}.dll"
                
                
                Add-Type -Path "$PSScriptRoot\..\OpenSource.Data.HashFunction\$DotNetVersionPathPart\OpenSource.Data.HashFunction.${AlgorithmName}.dll"


                 Write-Verbose "Loading algorithm Class : OpenSource.Data.HashFunction.${AlgorithmName}.${AlgoFactoryName}Factory"

                $HashFunctionType = "OpenSource.Data.HashFunction.${AlgorithmName}.${AlgoFactoryName}Factory" -as [Type]
                
                # only xxHash64 needs a Config during create
                If (${Algorithm} -eq 'xxHash64') {
                    $hasher = $HashFunctionType::Instance.Create($xxHashConfig)
                } Else {
                    $hasher = $HashFunctionType::Instance.Create()
                }

                $AlgorithmFound = $True
                $HashFunctionUsed = $True
            } Catch {
                Write-Error $_
                return
            }
        }

        if (-Not $AlgorithmFound)
        {
            $errorId = 'AlgorithmTypeNotSupported'
            $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errorMessage = [Microsoft.PowerShell.Commands.UtilityResources]::AlgorithmTypeNotSupported -f $Algorithm
            $exception = [System.InvalidOperationException]::New($errorMessage)
            $errorRecord = [System.Management.Automation.ErrorRecord]::New($exception, $errorId, $errorCategory, $null)
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        Write-Verbose "Using ${Algorithm} algorithm"

        function GetStreamHash
        {
            param(
                [System.IO.Stream]
                $InputStream,

                [System.String]
                $RelatedPath,

                #[System.Security.Cryptography.HashAlgorithm]
                $Hasher
            )

            # Compute file-hash using the crypto object
            
            If ($HashFunctionUsed) {
                [Byte[]]$computedHash = $Hasher.ComputeHash($InputStream).Hash
            } Else {
                [Byte[]]$computedHash = $Hasher.ComputeHash($InputStream)
            }
            
            [string]$hash = [BitConverter]::ToString($computedHash) -replace '-',''

            if ($RelatedPath -eq $null)
            {
                $retVal = [PSCustomObject] @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }
            }
            else
            {
                $retVal = [PSCustomObject] @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                    Path = $RelatedPath
                }
            }
            $retVal.psobject.TypeNames.Insert(0, 'Microsoft.Powershell.Utility.FileHash')
            $retVal
        }
    }
    
    process
    {
        if($PSCmdlet.ParameterSetName -eq 'Stream')
        {
            GetStreamHash -InputStream $InputStream -RelatedPath $null -Hasher $hasher
        }
        else
        {
            # TODO: using ListArray or other method (Get-Item) here 
            
            $pathsToProcess = @()
            if($PSCmdlet.ParameterSetName  -eq 'LiteralPath')
            {
                $pathsToProcess += Resolve-Path -LiteralPath $LiteralPath | Foreach-Object ProviderPath
            }
            if($PSCmdlet.ParameterSetName -eq 'Path')
            {
                $pathsToProcess += Resolve-Path $Path | Foreach-Object ProviderPath
            }

            foreach($filePath in $pathsToProcess)
            {
                
                Write-Verbose "Processing File: $filePath"
                
                if(Test-Path -LiteralPath $filePath -PathType Container)
                {
                    continue
                }

                try
                {
                    # Read the file specified in $FilePath as a Byte array
                    [system.io.stream]$stream = [system.io.file]::OpenRead($filePath)
                    GetStreamHash -InputStream $stream  -RelatedPath $filePath -Hasher $hasher
                }
                catch [Exception]
                {
                    $errorMessage = [Microsoft.PowerShell.Commands.UtilityResources]::FileReadError -f $FilePath, $_
                    Write-Error -Message $errorMessage -Category ReadError -ErrorId 'FileReadError' -TargetObject $FilePath
                    return
                }
                finally
                {
                    if($stream)
                    {
                        $stream.Dispose()
                    }
                }                            
            }
        }
    }
}
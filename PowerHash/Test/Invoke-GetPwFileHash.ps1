    <#
        Code to test all algorithms
        starting with PowerShell 5.1 and
        switching to PowerShell 6 / 7 with call of pwsh 
    #>

    Import-Module "$PSScriptRoot\..\..\PowerHash" -Force


    $algos = 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5','BernsteinHash','Blake2','Buzhash','CRC','ELF64','FNV1','FNV1a','Jenkins1','Jenkins2','MurmurHash3','Pearson','SpookyHashV1','SpookyHashV2','xxHash32','xxHash64','ModifiedBernsteinHash','MetroHash64','MetroHash128'

    ForEach ($Algo in $algos) {
        Get-PwFileHash -Path $PSCommandPath -Algorithm $Algo -ErrorAction continue -Verbose
    }


    # prevent endles loop in PS 6 / 7
    if($PSVersionTable.PSVersion.Major -gt 5) {
        return
    }


    # switching to Powershell 6 / 7
    
    pwsh.exe -ExecutionPolicy bypass -NoExit -File $PSCommandPath
<#
.SYNOPSIS
    Helper function to get a random seed to use in password creation.

.DESCRIPTION
    Helper function to get a random seed to use in password creation.
#>
Function Get-PasswordRandomSeed {
    $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
    $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
    $Random.GetBytes($RandomBytes)
    [BitConverter]::ToUInt32($RandomBytes, 0)
}

<#
.Synopsis
    Generates one or more complex passwords designed to fulfill the requirements for Active Directory

.DESCRIPTION
    Generates one or more complex passwords designed to fulfill the requirements for Active Directory

.EXAMPLE
    Get-RandomPassword
    C&3SX6Kn

    Will generate one password with a length between 8  and 12 chars.

.EXAMPLE
    Get-RandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
    7d&5cnaB
    !Bh776T"Fw
    9"C"RxKcY
    %mtM7#9LQ9h

    Will generate four passwords, each with a length of between 8 and 12 chars.

.EXAMPLE
    Get-RandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
    3ABa

    Generates a password with a length of 4 containing atleast one char from each InputString

.EXAMPLE
    Get-RandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
    3ABa

    Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
    the string specified with the parameter FirstChar

.OUTPUTS
    [String]

.NOTES
    Written by Simon Wåhlin, blog.simonw.se
    I take no responsibility for any issues caused by this script.

.FUNCTIONALITY
    Generates random passwords

.LINK
    http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
   
#>
function Get-RandomPassword {
    
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param(
        
        # Specifies minimum password length
        [Parameter(Mandatory=$false, ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false, ParameterSetName='RandomLength')]
        [ValidateScript({
            if ($_ -ge $MinPasswordLength){$true}
            else{Throw 'Max value cannot be lesser than min value.'}
        })]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false, ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 8,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnopqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '1234567890', '!@#$%^&*+='),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    
    begin {}
    
    process {

        for ( $iteration = 1; $iteration -le $Count; $iteration++ ) {

            $Password = @{}

            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if ( $PSCmdlet.ParameterSetName -eq 'RandomLength' ) {

                # If password length is set, use set length
                if ( $MinPasswordLength -eq $MaxPasswordLength ) {

                    $PasswordLength = $MinPasswordLength
                
                }
                
                # Otherwise randomize password length
                else {
                
                    $PasswordLength = ((Get-PasswordRandomSeed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if ( $PSBoundParameters.ContainsKey('FirstChar') ) {

                $Password.Add(0,$FirstChar[((Get-PasswordRandomSeed) % $FirstChar.Length)])

            }

            # Randomize one char from each group
            foreach ( $Group in $CharGroups ) {

                if ( $Password.Count -lt $PasswordLength ) {
                    
                    $Index = Get-PasswordRandomSeed

                    while ( $Password.ContainsKey($Index) ) {
                    
                        $Index = Get-PasswordRandomSeed                        

                    }

                    $Password.Add( $Index,$Group[((Get-PasswordRandomSeed) % $Group.Count)] )
                }
            }

            # Fill out with chars from $AllChars
            for ( $i=$Password.Count; $i -lt $PasswordLength; $i++ ) {
                
                $Index = Get-PasswordRandomSeed
                
                while ( $Password.ContainsKey($Index) ) {

                    $Index = Get-PasswordRandomSeed                        

                }

                $Password.Add($Index,$AllChars[((Get-PasswordRandomSeed) % $AllChars.Count)])
            }

            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))

        } # end main loop

    } # end process

    end {}
}

Export-ModuleMember -Function Get-RandomPassword
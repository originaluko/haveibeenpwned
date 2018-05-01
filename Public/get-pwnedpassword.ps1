#Requires -Version 3
function Get-PwnedPassword 
{
    <#
            .SYNOPSIS
            Report if an password has been found via the https://haveibeenpwned.com API service.
 
            .DESCRIPTION
            Report if an passsword has been found via the https://haveibeenpwned.com API service.

            This function queries the https://haveibeenpwned.com API service created by Troy Hunt (@troyhunt)
            and reports whether the specified password has been found (pwned).  The password can be in 
            clear text, a SHA1 hash, or a secure string.
            
            Note that if a secure string is used it has to be retrieved and then passed in the body
            of the https request.  Use this if you don't want to type a password in clear text at the CLI.

            .EXAMPLE
            Get-PwnedPassword -Password monkey
            Identifies if the password has been found.

            .EXAMPLE
            Get-PwnedPassword -SHA1 AB87D24BDC7452E55738DEB5F868E1F16DEA5ACE
            Identifies if the SHA1 hash of the password has been found.

            .EXAMPLE
            $Password = Read-host -AsSecureString
            Get-PwnedPassword -SecureString $Password
            Identifies if the password, in the SecureString variable $Password, has been found

            .EXAMPLE 
            $password = ConvertTo-SecureString "monkey" -asplaintext -force
            get-pwnedpassword -SecureString $password
            Identifies if the password, in the SecureString variable $Password, has been found
            
            .INPUTS
            None
 
            .NOTES
            Author:  Mark Ukotic
            Website: http://blog.ukotic.net
            Twitter: @originaluko
            GitHub:  https://github.com/originaluko/

            .LINK
            https://github.com/originaluko/haveibeenpwned

    #>
    
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Password')]
        [string]$Password,
        
        [Parameter(Mandatory, ParameterSetName = 'SecureString')]
        [SecureString]$SecureString,
        
        [Parameter(Mandatory, ParameterSetName = 'SHA1')]
        [ValidatePattern('^[0-9A-F]{40}$')]
        [string]$SHA1
    )


    Begin
    {

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $baseuri = "https://api.pwnedpasswords.com/range/"
        function Hash($textToHash)
        {      
            $hasher = new-object -TypeName "System.Security.Cryptography.SHA1CryptoServiceProvider"
            $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash)
            $bytes = $hasher.ComputeHash($toHash)
            $res = ($bytes|ForEach-Object ToString X2) -join ''
            $res
        }
      
    }
    Process
    {

        Switch ($PSCmdlet.ParameterSetName) {
            'Password' {
                $SHA1 = Hash($Password)
                write-host $SHA1                
                break
            }
            'SecureString' {
                $Password = (New-Object PSCredential "user", $SecureString).GetNetworkCredential().Password
                $SHA1 = Hash($Password)
                break
            }
            'SHA1' {
                break
            }
        }
        $URI = $baseuri + $SHA1.SubString(0,5)
        try
        {
            $Request = Invoke-RestMethod -Uri $URI
            $suffix = $SHA1.SubString(5,35) + ":"
            $found = $request.split('') | select-string "$suffix" | out-string
            if ($found) {
                $cnt = $found.SubString(38,10) 
                Write-Warning  "Password pwned $cnt times!"
            } else {
                Write-Output  'Password not found.'
            }
        }
         catch [System.Net.WebException] {
            Switch ($_.Exception.Message) {
                'The remote server returned an error: (400) Bad Request.' {
                    Write-Error -Message 'Bad Request - the account does not comply with an acceptable format.'
                }
                'The remote server returned an error: (403) Forbidden.' {
                    Write-Error -Message 'Forbidden - no user agent has been specified in the request.'
                }
                'The remote server returned an error: (404) Not Found.' {
                    Write-Output  'Password not found.'
                }
                'The remote server returned an error: (429) Too Many Requests.' {
                    Write-Error -Message 'Too many requests - the rate limit has been exceeded.'
                }
            }
            break
        }
    }
}

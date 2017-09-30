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
        [string]$SHA1
    )


    Begin
    {
        Switch ($PSCmdlet.ParameterSetName) {
            'Password' {
                $URI = "https://haveibeenpwned.com/api/v2/pwnedpassword/$Password"
                break
            }
            'SecureString' {
                $Password = (New-Object PSCredential "user", $SecureString).GetNetworkCredential().Password
                $URI = "https://haveibeenpwned.com/api/v2/pwnedpassword"
                $body = "Password=$Password"
                break
            }
            'SHA1' {
                $URI = "https://haveibeenpwned.com/api/v2/pwnedpassword/$SHA1"
                break
            }
        }
       
    }
    Process
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try
        {
            if ($PSCmdlet.ParameterSetName -eq 'SecureString') {
                Invoke-RestMethod -Uri $uri -Method Post -Body $body
            } 
            else {
                $Request = Invoke-RestMethod -Uri $URI
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
        Write-Warning  'Password pwned!' 
    }
}

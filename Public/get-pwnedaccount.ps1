#Requires -Version 3
Function Get-PwnedAccount 
{
    <#
            .SYNOPSIS
            Report if an account has been breached via the https://haveibeenpwned.com API service.
 
            .DESCRIPTION
            Report if an account has been breached via the https://haveibeenpwned.com API service.

            This function queries the https://haveibeenpwned.com API service created by Troy Hunt (@troyhunt)
            and reports whether the account (email address / username) specified has been found (pwned). 

            .EXAMPLE
            Get-PwnedAccount -EmailAdddress email@domain.com
            Retuns all accounts that have been pwned via the supplied email address / username.

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
    Param (
        [Parameter(Mandatory)]
        [ValidatePattern('(\w+@[]a-zA-Z_]+?\.[a-zA-Z]{2,6})')]
        [string]$EmailAddress
    )


    Begin
    {
        $URI = "https://haveibeenpwned.com/api/v2/breachedaccount/$EmailAddress"
    }
    Process
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try
        {
            $Request = Invoke-RestMethod -Uri $URI
        }
         Catch [System.Net.WebException] {
            Switch ($_.Exception.Message) {
                'The remote server returned an error: (400) Bad Request.' {
                    Write-Error -Message 'Bad Request - the account does not comply with an acceptable format.'
                }
                'The remote server returned an error: (403) Forbidden.' {
                    Write-Error -Message 'Forbidden - no user agent has been specified in the request.'
                }
                'The remote server returned an error: (404) Not Found.' {
                    $Response = New-Object PSObject -Property @{
                        'Account Exists' = 'False'
                        'Status' = 'Good'
                        'Description' = 'Email address not found.'
                    }
                }
                'The remote server returned an error: (429) Too Many Requests.' {
                    Write-Error -Message 'Too many requests - the rate limit has been exceeded.'
                }
            }
            $Response
            Return
        }
        $Request 
    }
}

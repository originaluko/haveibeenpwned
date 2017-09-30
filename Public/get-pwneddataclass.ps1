#Requires -Version 3
function Get-PwnedDataClass
{
    <#
            .SYNOPSIS
            Returns all Data Classes available via the https://haveibeenpwned.com API service.
 
            .DESCRIPTION
            Returns all Data Classes available via the https://haveibeenpwned.com API service.

            This function queries the https://haveibeenpwned.com API service created by Troy Hunt (@troyhunt)
            and reports all Data Classes used.  A Data Class is an attribute of a record compromised
            in a breach. 

            .EXAMPLE
            Get-PwnedDataClass
            Retuns all Data Classes used by https://haveibeenpwned.com 

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
    
    Begin
    {
        $URI = "https://haveibeenpwned.com/api/v2/dataclasses"
    }
    Process
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try
        {
            $Request = Invoke-RestMethod -Uri $URI
        }
         catch [System.Net.WebException] {
            Switch ($_.Exception.Message) {
                'The remote server returned an error: (400) Bad Request.' {
                    Write-Error -Message 'Bad Request.'
                }
                'The remote server returned an error: (403) Forbidden.' {
                    Write-Error -Message 'Forbidden - no user agent has been specified in the request.'
                }
                'The remote server returned an error: (404) Not Found.' {
                    Write-Output  'Not Found - No data class results found.'
                }
                'The remote server returned an error: (429) Too Many Requests.' {
                    Write-Error -Message 'Too many requests - the rate limit has been exceeded.'
                }
            }
            break
        }
        $Request 
    }
}

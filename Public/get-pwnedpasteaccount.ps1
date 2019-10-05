#Requires -Version 3
function Get-PwnedPasteAccount {
    <#
            .SYNOPSIS
            Report all pastes of an account via the https://haveibeenpwned.com API service.

            .DESCRIPTION
            Report all pastes of an account via the https://haveibeenpwned.com API service.

            This function queries the https://haveibeenpwned.com API service created by Troy Hunt (@troyhunt)
            and reports all pastres of the account along with the source and occurances. 

            This function requires the use of an API key!

            .EXAMPLE
            Get-PwnedPasteAccount -EmailAdddress email@domain.com -apiKey "hibp-api-key"
            Retuns all pastes of the account along with the source and occurances

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
        [Parameter(Mandatory, ValueFromPipeline=$true, ValueFromPipelineByPropertyName)]
        [ValidateScript( {
                New-Object -TypeName System.Net.Mail.MailAddress -ArgumentList @($_)
            })]
        [string]$EmailAddress,

        [ValidatePattern('\w')]
        [string]$UserAgent = "HaveIBeenPwned Powershell Module",

        [ValidatePattern('\w')]
        [string]$apiKey
    )


    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("hibp-api-key", $apiKey)
    }
    
    Process {

        try {
            $EmailAddress = (New-Object -TypeName System.Net.Mail.MailAddress -ArgumentList @($EmailAddress)).Address
            $URI = "https://haveibeenpwned.com/api/v3/pasteaccount/$EmailAddress"
            $Request = Invoke-RestMethod -Uri $URI -UserAgent $userAgent -Headers $headers
        }
        catch {
            $errorDetails = $null
            $response = $_.Exception | Select-Object -ExpandProperty 'message' -ErrorAction Ignore
            if ($response) {
                $errorDetails = $_.ErrorDetails
            }
                
            if ($null -eq $errorDetails) {
                Switch ($response) {
                    'The remote server returned an error: (400) Bad Request.' {
                        Write-Error -Message 'Bad Request - the account does not comply with an acceptable format.'
                    }
                    'The remote server returned an error: (403) Forbidden.' {
                        Write-Error -Message 'Forbidden - no user agent has been specified in the request.'
                    }
                    # Windows PowerShell 404 response
                    'The remote server returned an error: (404) Not Found.' {
                        $Response = New-Object PSObject -Property @{
                            'Account Exists' = 'False'
                            'Status'         = 'Good'
                            'Description'    = 'Email address not found.'
                        }
                    }
                    # PowerShell Core 404 response
                    'Response status code does not indicate success: 404 (Not Found).' {
                        $Response = New-Object PSObject -Property @{
                            'Account Exists' = 'False'
                            'Status'         = 'Good'
                            'Description'    = 'Email address not found.'
                        }
                    }
                    'The remote server returned an error: (429) Too Many Requests.' {
                        Write-Error -Message 'Too many requests - the rate limit has been exceeded.'
                    }
                }
            }
            else {
                Write-error -Message ('Request to "{0}" failed: {1}' -f $uri, $errorDetails)
            }
            $Response
            Return
        }
        $Request 
    }
}

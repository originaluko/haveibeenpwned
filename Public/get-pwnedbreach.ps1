#Requires -Version 3
Function Get-PwnedBreach {
    <#
            .SYNOPSIS
            Report breached sites via the https://haveibeenpwned.com API service.

            .DESCRIPTION
            Report breached sites via the https://haveibeenpwned.com API service.

            This function queries the https://haveibeenpwned.com API service created by Troy Hunt (@troyhunt)
            and reports breached sites.  Returned with the breached site are the details surrounding the 
            breach and source of the original dump.

            .EXAMPLE
            Get-PwnedBreach
            Retuns all breached sites.

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
    
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $userAgent = "HaveIBeenPwned Powershell Module"
        $URI = 'https://haveibeenpwned.com/api/v3/breaches'
    }
    
    Process {

        try {
            $Request = Invoke-RestMethod -Uri $URI -UserAgent $userAgent
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
                        Write-Output  'Not Found - No breach results found.'
                    }
                    # PowerShell Core 404 response
                    'Response status code does not indicate success: 404 (Not Found).' {
                        Write-Output  'Not Found - No breach results found.'
                    }
                    'The remote server returned an error: (429) Too Many Requests.' {
                        Write-Error -Message 'Too many requests - the rate limit has been exceeded.'
                    }
                }
            }
            else {
                Write-error -Message ('Request to "{0}" failed: {1}' -f $uri, $errorDetails)
            }
            break
        }
        $Request 
    }
}

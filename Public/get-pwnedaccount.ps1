#Requires -Version 3
Function Get-PwnedAccount {
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

            .EXAMPLE
            Get-PwnedAccount -EmailAdddress email@domain.com -UserAgent "My User Agent"
            Same as Example 1 but specifies a custom User Agent String.

            .EXAMPLE
            Get-PwnedAccount -csv c:\temp\emailaddress.csv 
            Imports a list of email addresses in csv format.  Each email address being a seperate row.

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
    
    [CmdletBinding(DefaultParameterSetName = 'email')]
    [OutputType([object])]
    Param (
        [Parameter(Mandatory, ValueFromPipeline=$true, ValueFromPipelineByPropertyName, ParameterSetName = 'email', Position=0)]
        [ValidateScript( {
                New-Object -TypeName System.Net.Mail.MailAddress -ArgumentList @($_)
            })]
        [string]$EmailAddress,

        [Parameter(Mandatory, ParameterSetName = 'csv')]
        [System.IO.FileInfo]$CSV,

        [ValidatePattern('\w')]
        [string]$UserAgent = “HaveIBeenPwned Powershell Module”
    )

    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    Process {
       
        Switch ($PSCmdlet.ParameterSetName) {
            'email' {
                try {
                    # Parse the email address with .Net framework type and get the address part out, 
                    # e.g. ignoring the display name in '"bob" <bob@example.com>'
                    # and returning 'bob@example.com'
                    $EmailAddress = (New-Object -TypeName System.Net.Mail.MailAddress -ArgumentList @($EmailAddress)).Address
                    $URI = "https://haveibeenpwned.com/api/v2/breachedaccount/$EmailAddress"
                    $Request = Invoke-RestMethod -Uri $URI -UserAgent $UserAgent
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
                                $response = New-Object PSObject -Property @{
                                    'Account Exists' = 'False'
                                    'Status'         = 'Good'
                                    'Description'    = 'Email address not found.'
                                }
                            }
                            # PowerShell Core 404 response
                            'Response status code does not indicate success: 404 (Not Found).' {
                                $response = New-Object PSObject -Property @{
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
                    $response
                    return 
                }
                $request
            }
            'csv' {
                $csvImport = Import-Csv -Path $CSV -Header "Accounts"
                foreach ($email in $csvImport) {
                    try { 
                        
                        $emailAddress = $email.accounts
                        $URI = "https://haveibeenpwned.com/api/v2/breachedaccount/$EmailAddress"
                        $Request = Invoke-RestMethod -Uri $URI -UserAgent $UserAgent
                        foreach ($result in $request) { 
                            $breach = $result.title
                            $response = New-Object PSObject -Property @{
                                'Email'       = "$emailAddress"
                                'Breach'      = "$breach"
                                'Description' = 'Email address found in breach'
                            }
                            $response
                        }
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
                                # Windows PowerSHell 404 response
                                'The remote server returned an error: (404) Not Found.' {
                                    # Don't want any output for csv response
                                }
                                # PowerShell Core 404 response
                                'Response status code does not indicate success: 404 (Not Found).' {
                                    # Don't want any output for csv response
                                }
                                'The remote server returned an error: (429) Too Many Requests.' {
                                    Write-Error -Message 'Too many requests - the rate limit has been exceeded.'
                                }
                            }
                        }
                        else {
                            Write-error -Message ('Request to "{0}" failed: {1}' -f $uri, $errorDetails)
                        }
                    }
                }
            }
        }
    }
}

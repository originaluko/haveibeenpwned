HaveIBeenPwned
============================

Identify pwned accounts and passwords via the "Have I been pwned?" (https://haveibeenpwned.com) API.

This module has been updated to the HIBP v3 API which now requires authorisation in the form of an API Key.
https://haveibeenpwned.com/API/v3#APIVersion

Use of some of these functions requires an API key.  This module does not come with an API key.
An API key can be obtained from https://haveibeenpwned.com/API/Key

# Requirements

At a minimum, make sure you have installed the following:

1. Windows PowerShell 3+ or PowerShell Core
2. (optional) [Windows Management Framework 5.1](https://www.microsoft.com/en-us/download/details.aspx?id=54616)

# Installation & Execution

##### Option 1: PowerShellGallery

Module can be installed from the PowerShellGalley (requires PowerShell 5+)
1. Install-Module -Name HaveIBeenPwned

##### Option 2: Manual

1. Download the latest version to your desktop.
2. Open a PowerShell console.
3. Run `Set-ExecutionPolicy` using the parameter `RemoteSigned` or `Bypass`.
4. Import the Module


# Usage Instructions

HIBP v3 API now `requires` the use of an API Key.  Make sure you are using one.
The API Key can be stored as a variable and specified with the -apiKey parameter.

Examples:

Get-PwnedAccount -EmailAdddress email@domain.com -apiKey "xxxxxxxxxxxxxxx"\
Retuns all accounts that have been pwned via the supplied email address / username.

Get-PwnedAccount -csv c:\temp\emailaddress.csv -apiKey "xxxxxxxxxxxxxxx"\
Imports a list of email addresses in csv format.  Each email address being a seperate row.

Get-PwnedPassword -Password monkey\
Identifies if the password has been found. *No API key required

Get-PwnedPassword -Password monkey -Padding false\
Identifies if the password has been found with response padding removed. *No API key required

$Password = Read-host -AsSecureString\
Get-PwnedPassword -SecureString $Password
Identifies if the password, in the SecureString variable $Password, has been found

Get-PwnedPassword -SHA1 AB87D24BDC7452E55738DEB5F868E1F16DEA5ACE\
Identifies if the SHA1 hash of the password has been found. *No API key required

Further examples for each function can be found by typing\
Get-Help {function name} -Examples

# Future

Testing with an API Key!

# Issues

The HIBP API now requires the use of a UserAgent.  Old versions didn't specify this by default.
Always make sure you're running the latest version.  

If using the CSV import functionality of Get-PwnedAccount.  The default 1500 millisecond delay
between checking pwned accounts may not be large enough and cause rate-limiting.  Increasing
the rate limit can be achieved with parameter "RateLimit" and increasing the value above 1500.

# Licensing

The MIT License (MIT)

Copyright (c) 2019 [ukotic.net](http://blog.ukotic.net)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

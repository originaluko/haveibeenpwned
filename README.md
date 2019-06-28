HaveIBeenPwned
============================

Identify pwned accounts and passwords via the "Have I been pwned?" (https://haveibeenpwned.com) API.

# Requirements

At a minimum, make sure you have installed the following:

1. Windows PowerShell 3+ or PowerShell Core
2. (optional) [Windows Management Framework 5.0](https://www.microsoft.com/en-us/download/details.aspx?id=50395)

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

Examples:

Get-PwnedAccount -EmailAdddress email@domain.com
Retuns all accounts that have been pwned via the supplied email address / username.

Get-PwnedAccount -csv c:\temp\emailaddress.csv 
Imports a list of email addresses in csv format.  Each email address being a seperate row.

Get-PwnedPassword -Password monkey
Identifies if the password has been found.

$Password = Read-host -AsSecureString
Get-PwnedPassword -SecureString $Password
Identifies if the password, in the SecureString variable $Password, has been found

Get-PwnedPassword -SHA1 AB87D24BDC7452E55738DEB5F868E1F16DEA5ACE
Identifies if the SHA1 hash of the password has been found.

# Future

Improve error handling

# Issues

The HIBP API now requires the use of a UserAgent.  Old versions didn't specify this by default.
Always make sure you're running the latest version.  

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

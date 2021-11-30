<#
.Synopsis
   Detects PowerShell scripts with unicode characters known for use in Trojan Source attacks
.DESCRIPTION
   Detects PowerShell scripts with unicode characters known for use in Trojan Source attacks
.PARAMETER Path
   Path to the directory you want to check for scripts with suspicious unicode characters
.EXAMPLE
   Get-TrojanSourceSuspectFiles -Path "C:\temp"
.NOTES
  Author: Paul Harrison
  Date written: 11/30/2021
#>
function Get-TrojanSourceSuspectFiles
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})]
        [string]
        $Path
    )

    Begin
    {
        "`u{2195} - If vertical arrows were just displayed then you're good to run the rest of this otherwise try it again in PS Core. Press 'y' to continue."
        $Key = $Host.UI.RawUI.ReadKey()
        If(([string]($Key.Character)).ToUpper() -ne 'Y'){
            "Process terminated as per user input"
            return
        }
        $BadChars = "[`u{202A}`u{202B}`u{202D}`u{202E}`u{2066}`u{2067}`u{2068}`u{202C}`u{2069}]" #regex to find bad characters
        $results = @()
    }
    Process
    {
        $results += gci $Path -Recurse -Include @("*.ps1","*.psm1","*.txt") | %{
            $fileContents = gc $_.FullName
            If($fileContents -match $BadChars -or $fileContents.Contains('`u{202A}') -or $fileContents.Contains('`u{202a}') -or $fileContents.Contains('`u{202B}') -or $fileContents.Contains('`u{202b}') -or $fileContents.Contains('`u{202D}') -or $fileContents.Contains('`u{202d}') -or $fileContents.Contains('`u{202E}') -or $fileContents.Contains('`u{202e}') -or $fileContents.Contains('`u{2066}') -or $fileContents.Contains('`u{2067}') -or $fileContents.Contains('`u{2068}') -or $fileContents.Contains('`u{2069}') -or $fileContents.Contains('`u{202C}') -or $fileContents.Contains('`u{202c}')){
                $_.FullName
            }
        }

    }
    End
    {
        If($results.count -gt 0){
        write-host "Items with suspicious characters found!" -ForegroundColor Red -BackgroundColor Black
        $results
        }Else{
            'No items with suspicious characters found'
        }
    }
}

$DscResourcePath   = Join-Path -Path $PSScriptRoot -ChildPath '..\..\cRemoteDesktopServices'
$ConfigurationFile = Join-Path -Path $PSScriptRoot -ChildPath 'Configuration.psm1'
$ConfigDataFile    = Join-Path -Path $PSScriptRoot -ChildPath 'Configuration.psd1'
$Credential        = Get-Credential
$OutputPath        = Join-Path -Path (Get-Location) -ChildPath 'Output'

Copy-Item -Path $DscResourcePath -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -Force

Import-Module $ConfigurationFile -Force

$ConfigData = Invoke-Expression -Command (Get-Content -Raw -Path $ConfigDataFile)
RdsSessionDeployment -Credential $Credential -ConfigurationData $ConfigData -OutputPath $OutputPath

$DscResourcePath   = Join-Path -Path $PSScriptRoot -ChildPath 'cRemoteDesktopServices'
$ConfigurationFile = Join-Path -Path $PSScriptRoot -ChildPath 'Configuration.psm1'
$ConfigDataFile    = Join-Path -Path $PSScriptRoot -ChildPath 'Configuration.psd1'
$CredentialFile    = Join-Path -Path $PSScriptRoot -ChildPath 'Cred\administrator@DEMO.clixml'
$OutputPath        = Join-Path -Path $PSScriptRoot -ChildPath 'Output'

Copy-Item -Path $DscResourcePath -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -Force

Import-Module $ConfigurationFile -Force

$ConfigData = Invoke-Expression -Command (Get-Content -Raw -Path $ConfigDataFile)
RemoteDesktopSessionDeployment -Credential (Import-Clixml -Path $CredentialFile) -ConfigurationData $ConfigData -OutputPath $OutputPath
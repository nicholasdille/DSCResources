enum Ensure {
   Absent
   Present
}

enum RDCertificateRole {
    RDGateway
    RDWebAccess
    RDRedirector
    RDPublishing
}

enum NewConnectionAllowed {
    Yes
    NotUntilReboot
    No
}

enum LicensingMode {
    PerUser
    PerDevice
}

enum RDConnectionBrokenAction {
    None
    Disconnect
    Logoff
}

enum RDClientDeviceRedirectionOptions {
    None
    AudioVideoPlayBack
    AudioRecording
    COMPort
    PlugAndPlayDevice
    SmartCard
    Clipboard
    LPTPort
    Drive
    TimeZone
}

enum CommandLineSettingValue {
    Allow
    DoNotAllow
    Require
}

$RDEncryptionLevel = @{
    Low              = 0  # Low
    ClientCompatible = 1  # ClientCompatible
    High             = 2  # High
    FipsCompliant    = 3  # FipsCompliant
}

$RDClientDeviceRedirectionOption = @{
    None               = 0x0000  # None
    AudioVideoPlayBack = 0x0001  # AudioVideoPlayBack
    AudioRecording     = 0x0002  # AudioRecording
    COMPort            = 0x0004  # COMPort
    PlugAndPlayDevice  = 0x0008  # PlugAndPlayDevice
    SmartCard          = 0x0010  # SmartCard
    Clipboard          = 0x0020  # Clipboard
    LPTPort            = 0x0040  # LPTPort
    Drive              = 0x0080  # Drive
    TimeZone           = 0x0100  # TimeZone
}

$RDSecurityLayer = @{
    RDP       = 0  # RDP
    Negotiate = 1  # Negotiate
    SSL       = 2  # SSL
}

function Get-Fqdn {
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerName
    )

    PROCESS {
        foreach ($Name in $ComputerName) {
            Resolve-DnsName -Name $Name -Type A | Select-Object -ExpandProperty Name
        }
    }
}

[DscResource()]
class cRDSessionHost {

    #region Parameters
    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(Key)]
    [String]$ConnectionBroker

    [DscProperty()]
    [String]$SessionHost

    [DscProperty()]
    [String]$CollectionName
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential
    #endregion

    [Void] Set() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()

        $RDCB = $this.ConnectionBroker
        $RDSH = Get-Fqdn -ComputerName $env:COMPUTERNAME

        Write-Verbose ('Creating PowerShell session with credentials')
        $Session = $null
        try {
            $Session = New-PSSession -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential
        } catch {
            Write-Error ('Failed to create session to {0} with CredSSP as {1}' -f $env:COMPUTERNAME, $this.Credential.UserName)
        }

        Write-Verbose 'Testing for role'
        if ($Configuration['SessionHost'] -icontains (Get-Fqdn -ComputerName $env:COMPUTERNAME)) {
            if ($this.Ensure -ieq 'Present') {
                try {
                    Write-Verbose ('Adding session host <{0}> to connection broker <{1}>' -f $RDCB, $RDSH)
                    Invoke-Command -Session $Session -ScriptBlock {
                        Write-Verbose ('Extending deployment (RDCB={0} RDSH={1})' -f $Using:RDCB, $Using:RDSH)
                        Add-RDServer -ConnectionBroker $Using:RDCB -Server $Using:RDSH -Role RDS-RD-SERVER
                    }
                    Write-Verbose 'Done creating deplyoment without exception'

                } catch {
                    Write-Error ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
                }

            } elseif ($this.Ensure -ieq 'Absent') {
                try {
                    Write-Verbose ('Removing session host <{0}> from connection broker <{1}>' -f $RDCB, $RDSH)
                    Invoke-Command -Session $Session -ScriptBlock {
                        Write-Verbose ('Removing session host (RDCB={0} RDSH={1})' -f $Using:RDCB, $Using:RDSH)
                        Remove-RDServer -ConnectionBroker $Using:RDCB -Server $Using:RDSH -Role RDS-RD-SERVER
                    }
                    Write-Verbose 'Done creating deplyoment without exception'

                } catch {
                    Write-Error ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
                }
            }
        }

        Write-Verbose 'Testing for collection'
        if (-not $Configuration['CollectionName'] -or $Configuration['CollectionName'] -eq $null) {
            $Collection = $this.CollectionName

            if ($this.Ensure -ieq 'Present') {
                try {
                    Write-Verbose ('Adding session host <{0}> to collection <{1}>' -f $RDCB, $Collection)
                    Invoke-Command -Session $Session -ScriptBlock {
                        Write-Verbose ('Extending deployment (RDCB={0} RDSH={1})' -f $Using:RDCB, $Using:RDSH)
                        Add-RDSessionHost -ConnectionBroker $Using:RDCB -CollectionName $Using:Collection -SessionHost $Using:RDSH
                    }
                    Write-Verbose 'Done creating deplyoment without exception'

                } catch {
                    Write-Error ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
                }

            } elseif ($this.Ensure -ieq 'Absent') {
                try {
                    Write-Verbose ('Removing session host <{0}> from collection <{1}>' -f $RDCB, $RDSH)
                    Invoke-Command -Session $Session -ScriptBlock {
                        Write-Verbose ('Removing session host (RDCB={0} RDSH={1})' -f $Using:RDCB, $Using:RDSH)
                        Remove-RDSessionHost -ConnectionBroker $Using:RDCB -CollectionName $Using:Collection -SessionHost $Using:RDSH
                    }
                    Write-Verbose 'Done creating deplyoment without exception'

                } catch {
                    Write-Error ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
                }
            }
        }
    }

    [Bool] Test() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()
        
        Write-Verbose ('Comparing request ({0}) and state ({1}). Returning {2}' -f $this.Ensure, $Configuration.Ensure, ($this.Ensure -ieq $Configuration.Ensure))
        return ($this.Ensure -ieq $Configuration.Ensure)
    }

    [cRDSessionHost] Get() {
        $Configuration = [hashtable]::new()
        $Configuration['Ensure']           = 'Absent'
        $Configuration['ConnectionBroker'] = $null
        $Configuration['SessionHost']      = $null
        $Configuration['CollectionName']   = $null
        $Configuration['Credential']       = $null

        Write-Verbose 'Initialized the hash table'

        try {
            Write-Verbose ('Calling Get-RDServer on connection broker <{0}>' -f $this.ConnectionBroker)
            $RDCB = $this.ConnectionBroker
            $Session = New-PSSession -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential
            $DeploymentRoles = Invoke-Command -Session $Session -ScriptBlock {
                Write-Verbose ('Calling Get-RDServer')
                Get-RDServer -ConnectionBroker $Using:RDCB -ErrorAction SilentlyContinue
            }
            $SessionHosts = Invoke-Command -Session $Session -ScriptBlock {
                Write-Verbose ('Calling Get-RDSessionCollection')
                Get-RDSessionCollection -ConnectionBroker $Using:RDCB -ErrorAction SilentlyContinue | ForEach-Object {
                    Get-RDSessionHost -ConnectionBroker $Using:RDCB -CollectionName $_.CollectionName -ErrorAction SilentlyContinue
                }
            }
            
            Write-Verbose 'Populating hash table'
            $Configuration['ConnectionBroker'] = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-CONNECTION-BROKER'} | Select-Object -ExpandProperty Server | Get-Fqdn
            $Configuration['SessionHost']      = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-RD-SERVER'}         | Select-Object -ExpandProperty Server | Get-Fqdn
            if ($Configuration['SessionHost'] -icontains (Get-Fqdn -ComputerName $env:COMPUTERNAME)) {
                $Configuration['Ensure'] = 'Present'
            }
            $Configuration['CollectionName'] = $SessionHosts | Where-Object {$_.SessionHost -ieq (Get-Fqdn -ComputerName $env:COMPUTERNAME)}
            if ($Configuration['Ensure'] -and -not $Configuration['CollectionName']) {
                $Configuration['Ensure'] = 'Absent'
            }

            Write-Verbose 'Done populating without exception'

        } catch {
            Write-Verbose 'Error populating'
        }

        Write-Verbose ('Returning hash table (RDCB={0}, RDSH={1})' -f ($Configuration['ConnectionBroker'] -join ','), ($Configuration['SessionHost'] -join ','))
        return $Configuration
    }
}

[DscResource()]
class cRDWebAccessHost {

    #region Parameters
    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(Key)]
    [String]$ConnectionBroker

    [DscProperty()]
    [String]$SessionHost
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential
    #endregion

    [Void] Set() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()

        Write-Verbose 'Testing for web access host'
        if ($this.Ensure -ieq 'Present' -and $Configuration.Ensure -ieq 'Absent') {
            try {
                $RDCB = $this.ConnectionBroker
                $RDWA = $env:COMPUTERNAME | Get-Fqdn
                Write-Verbose ('Adding web access host <{0}> to connection broker <{1}>' -f $RDCB, $RDWA)
                Invoke-Command -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential -ScriptBlock {
                    Write-Verbose ('Extending deployment (RDCB={0} RDWA={1})' -f $Using:RDCB, $Using:RDWA)
                    Add-RDServer -ConnectionBroker $Using:RDCB -Server $Using:RDWA -Role RDS-WEB-ACCESS
                }

                Write-Verbose 'Done extending deplyoment without exception'

            } catch {
                Write-Verbose ('Failed to extend deployment. Exception: {0}' -f $_.Exception.toString())
            }

        } elseif ($this.Ensure -ieq 'Absent' -and $Configuration.Ensure -ieq 'Present') {
            try {
                $RDCB = $this.ConnectionBroker
                $RDWA = $env:COMPUTERNAME | Get-Fqdn
                Write-Verbose ('Removing session host <{0}> from connection broker <{1}>' -f $RDCB, $RDWA)
                Invoke-Command -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential -ScriptBlock {
                    Write-Verbose ('Removing session host (RDCB={0} RDWA={1})' -f $Using:RDCB, $Using:RDWA)
                    Remove-RDServer -ConnectionBroker $Using:RDCB -Server $Using:RDWA -Role RDS-WEB-ACCESS
                }

                Write-Verbose 'Done remove web access from deplyoment without exception'

            } catch {
                Write-Verbose ('Failed to remove web access from deployment. Exception: {0}' -f $_.Exception.toString())
            }
        }
    }

    [Bool] Test() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()
        
        Write-Verbose ('Comparing request ({0}) and state ({1}). Returning {2}' -f $this.Ensure, $Configuration.Ensure, ($this.Ensure -ieq $Configuration.Ensure))
        return ($this.Ensure -ieq $Configuration.Ensure)
    }

    [cRDWebAccessHost] Get() {
        $Configuration = [hashtable]::new()
        $Configuration['Ensure']           = 'Absent'
        $Configuration['ConnectionBroker'] = $null
        $Configuration['WebAccessHost']    = $null
        $Configuration['Credential']       = $null

        Write-Verbose 'Initialized the hash table'

        try {
            Write-Verbose ('Calling Get-RDServer on connection broker <{0}>' -f $this.ConnectionBroker)
            $RDCB = $this.ConnectionBroker
            $DeploymentRoles = Invoke-Command -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential -ScriptBlock {
                Write-Verbose ('Calling Get-RDServer')
                Get-RDServer -ConnectionBroker $Using:RDCB -ErrorAction SilentlyContinue
            }
            
            Write-Verbose 'Populating hash table'
            $Configuration['ConnectionBroker'] = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-CONNECTION-BROKER'} | Select-Object -ExpandProperty Server | Get-Fqdn
            $Configuration['WebAccessHost']    = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-WEB-ACCESS'}        | Select-Object -ExpandProperty Server | Get-Fqdn
            if ($Configuration['WebAccessHost'] -icontains ($env:COMPUTERNAME | Get-Fqdn)) {
                $Configuration['Ensure'] = 'Present'
            }
            Write-Verbose 'Done populating without exception'

        } catch {
            Write-Verbose 'Error populating'
        }

        Write-Verbose ('Returning hash table (RDCB={0}, RDWA={1})' -f ($Configuration['ConnectionBroker'] -join ','), ($Configuration['WebAccessHost'] -join ','))
        return $Configuration
    }
}

[DscResource()]
class cRDSessionDeployment {

    #region Parameters
    [DscProperty(Key)]
    [string]$ConnectionBroker
 
    [DscProperty(Mandatory)]
    [String]$SessionHost
 
    [DscProperty(Mandatory)]
    [String]$WebAccess
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential
    #endregion

    [Void] Set() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()

        if ([string]::IsNullOrEmpty($Configuration.ConnectionBroker) -eq $false) {
            throw ('A RDS deployment is already present (RDCB={0} // RDWA={1} // RDSH={2})' -f ($Configuration.ConnectionBroker -join ','), ($Configuration.WebAccess -join ','), ($Configuration.SessionHost -join ','))
        }
	$CBFQDN = Get-FQDN $this.ConnectionBroker
	$SHFQDN	= Get-FQDN $this.Sessionhost
	$WAFQDN = Get-FQDN $this.WebAccess
        Write-Verbose 'Checking for quick deployment'
        if ($this.ConnectionBroker -ieq $env:COMPUTERNAME -and
            $this.WebAccess        -ieq $env:COMPUTERNAME -and
            $this.SessionHost      -ieq $env:COMPUTERNAME) {
            Write-Verbose "Creating new quick deployment: CB=$CBFQDN SH=$SHFQDN WA=$WAFQDN"
            Invoke-Command -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential -ScriptBlock {
                    Write-Verbose ('Creating new deployment using remoting RDCB={0} RDSH={1} RDWA={2}' -f $Using:CBFQDN, $Using:SHFQDN, $Using:WAFQDN)
                    New-RDSessionDeployment -ConnectionBroker $Using:CBFQDN -SessionHost $Using:SHFQDN -WebAccessServer $Using:WAFQDN
                }

            Write-Verbose 'Updating configuration'
            $Configuration = $this.Get()
        }

        if ($Configuration.ConnectionBroker -eq $null) {
            Write-Verbose ('Creating new deployment RDCB={0} RDSH={1} RDWA={2}' -f $env:COMPUTERNAME, $this.SessionHost, $this.WebAccess)

            try {
                $RDCB = $env:COMPUTERNAME
                $RDWA = $this.WebAccess
                $RDSH = $this.SessionHost
                Invoke-Command -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential -ScriptBlock {
                    Write-Verbose ('Creating new deployment using remoting RDCB={0} RDSH={1} RDWA={2}' -f $Using:RDCB, $Using:RDSH, $Using:RDWA)
                    New-RDSessionDeployment -ConnectionBroker $Using:RDCB -SessionHost $Using:RDSH -WebAccessServer $Using:RDWA
                }
                Write-Verbose 'Done creating deplyoment without exception'

                Write-Verbose 'Updating configuration'
                $Configuration = $this.Get()

            } catch {
                Write-Verbose ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
            }
        }

        Write-Verbose 'Done'
    }

    [Bool] Test() {
	
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()
	write-verbose $Configuration
        Write-Verbose 'Checking for RDCB role'
        if ([string]::IsNullOrEmpty($Configuration.ConnectionBroker)) {
            Write-Verbose 'No deployment present. Returning $false'
            return $false

        } else {
            Write-Verbose 'Deployment present. Returning $true'
            return $true
        }
    }

    [cRDSessionDeployment] Get() {
        $Configuration = [hashtable]::new()
<<<<<<< HEAD
=======
        $Configuration['Ensure']           = 'Absent'
>>>>>>> 40f370576b269867976ef24746033ee713046765
        $Configuration['ConnectionBroker'] = $null
        $Configuration['SessionHost']      = $null
        $Configuration['WebAccess']        = $null
        $Configuration['Credential']       = $null

        Write-Verbose 'Initialized the hash table'

        try {
            Write-Verbose ('Calling Get-RDServer on connection broker <{0}>' -f $this.ConnectionBroker)
            $RDCB = $this.ConnectionBroker

            $Session = New-PSSession -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential
            $DeploymentRoles = Invoke-Command -Session $Session -ScriptBlock {
                Write-Verbose ('Calling Get-RDServer')
                Get-RDServer -ConnectionBroker $Using:RDCB -ErrorAction SilentlyContinue
            }
            
            Write-Verbose 'Populating hash table'
            $Configuration['ConnectionBroker'] = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-CONNECTION-BROKER'} | Select-Object -ExpandProperty Server | Get-Fqdn
            $Configuration['SessionHost']      = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-RD-SERVER'}         | Select-Object -ExpandProperty Server | Get-Fqdn
            if ($Configuration['SessionHost'] -icontains (Get-Fqdn -ComputerName $env:COMPUTERNAME)) {
                $Configuration['Ensure'] = 'Present'
            }

            Write-Verbose 'Done populating without exception'

        } catch {
            Write-Verbose 'Error populating'
        }

        Write-Verbose ('Returning hash table (RDCB={0}, RDSH={1}, RDWA={2})' -f ($Configuration['ConnectionBroker'] -join ','), ($Configuration['SessionHost'] -join ','), ($Configuration['WebAccess'] -join ','))
        return $Configuration
    }
}

[DscResource()]
class cRDCertificate {
 
    #region Parameters
    [DscProperty(Key)]
    [String]$ConnectionBroker

    [DscProperty(Mandatory)]
    [string]$Path
 
    [DscProperty()]
    [SecureString]$Password
 
    [DscProperty()]
    [RDCertificateRole[]]$Role
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential
    #endregion

    [Void] Set() {
        #https://technet.microsoft.com/en-us/library/jj215464%28v=wps.630%29.aspx
        #Set-RDCertificate
    }

    [Bool] Test() {return $false}

    [cRDCertificate] Get() {
        $Configuration = [hashtable]::new()
        $Configuration.Add('RDCB', '')
        $Configuration.Add('Ensure',           'Absent')

        return $Configuration
    }
<<<<<<< HEAD
=======
}

[DscResource()]
class cRDSHConfiguration {
 
    #region Parameters
    [DscProperty(Key)]
    [String]$ConnectionBroker

    [DscProperty(Mandatory)]
    [NewConnectionAllowed]$NewConnectionAllowed
 
    [DscProperty()]
    [string[]]$LicenseServer
 
    [DscProperty()]
    [LicensingMode]$LicensingMode
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential
    #endregion

    [Void] Set() {
        #Set-RDSessionHost -ConnectionBroker $this.ConnectionBroker -SessionHost $env:COMPUTERNAME -NewConnectionAllowed $this.NewConnectionAllowed
        #Set-RDLicensingConfiguration -ConnectionBroker $this.ConnectionBroker -LicenseServer $this.LicenseServer -Mode $this.LicensingMode
    }

    [Bool] Test() {return $false}

    [cRDSHConfiguration] Get() {
        $Configuration = [hashtable]::new()
        $Configuration.Add('RDCB', '')
        $Configuration.Add('Ensure',           'Absent')

        return $Configuration
    }
}

[DscResource()]
class cRDSessionCollection {

    #region parameters
    [DscProperty(Key)]
    [String]$ConnectionBroker

    [DscProperty(Mandatory)]
    [string]$Name

    [DscProperty()]
    [string]$Description
 
    [DscProperty(Mandatory)]
    [string[]]$SessionHost

    [DscProperty()]
    [string[]]$UserGroup

    [DscProperty()]
    [bool]$AuthenticateUsingNLA

    [DscProperty()] # BUILD FROM $RDEncryptionLevel
    [string]$EncryptionLevel

    [DscProperty()] # BUILD FROM $RDSecurityLayer
    [string]$SecurityLayer

    #LoadBalancing
    #PS C:\> $LoadBalanceObjectsArray = New-Object System.Collections.Generic.List[Microsoft.RemoteDesktopServices.Management.RDSessionHostCollectionLoadBalancingInstance] 
    #PS C:\>$LoadBalanceSessionHost1 = New-Object Microsoft.RemoteDesktopServices.Management.RDSessionHostCollectionLoadBalancingInstance( "SessionHostCollection", 50, 200, "RDSH-1.Contoso.com" )
    #PS C:\> $LoadBalanceObjectsArray.Add($LoadBalanceSessionHost1)
    #PS C:\> $LoadBalanceSessionHost2 = New-Object Microsoft.RemoteDesktopServices.Management.RDSessionHostCollectionLoadBalancingInstance( "SessionHostCollection", 50, 300, "RDSH-2Contoso.com" )
    #PS C:\> $LoadBalanceObjectsArray.Add($LoadBalanceSessionHost2)
    #PS C:\> Set-RDSessionCollectionConfiguration -CollectionName "Session Collection 07" -LoadBalancing $LoadBalanceObjectsArray -ConnectionBroker "RDCB.Contoso.com"

    [DscProperty()]
    [int]$ActiveSessionLimitMin
    
    [DscProperty()]
    [int]$DisconnectedSessionLimitMin

    [DscProperty()]
    [int]$IdleSessionLimitMin

    [DscProperty()]
    [bool]$AutomaticReconnectionEnabled

    [DscProperty()]
    [RDConnectionBrokenAction]$BrokenConnectionAction

    [DscProperty()] # BUILT FROM $RDClientDeviceRedirectionOptions
    [RDClientDeviceRedirectionOptions[]]$ClientDeviceRedirectionOptions

    [DscProperty()]
    [bool]$ClientPrinterAsDefault

    [DscProperty()]
    [bool]$ClientPrinterRedirected

    [DscProperty()]
    [int]$MaxRedirectedMonitors

    [DscProperty()]
    [bool]$RDEasyPrintDriverEnabled

    [DscProperty()]
    [bool]$TemporaryFoldersDeletedOnExit

    [DscProperty()]
    [bool]$TemporaryFoldersPerSession
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential
    #endregion

    [Void] Set() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()

        $RDCB = $this.ConnectionBroker

        Write-Verbose ('Creating PowerShell session with credentials')
        $Session = $null
        try {
            $Session = New-PSSession -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential
        } catch {
            Write-Error ('Failed to create session to {0} with CredSSP as {1}' -f $env:COMPUTERNAME, $this.Credential.UserName)
        }

        Write-Verbose 'Testing for existence'
        if (-not $Configuration['Name'] -or $Configuration['Name'] -eq $null) {
            $Collection = $this.Name
            if ($this.Ensure -ieq 'Present') {
                try {
                    Write-Verbose ('Adding collection <{0}>' -f $Collection)
                    Invoke-Command -Session $Session -ScriptBlock {
                        Write-Verbose ('Extending deployment')
                        New-RDSessionCollection -ConnectionBroker $Using:RDCB -CollectionName $Using:Collection -SessionHost $this.SessionHost
                    }
                    Write-Verbose 'Done creating deplyoment without exception'

                } catch {
                    Write-Error ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
                }

            } elseif ($this.Ensure -ieq 'Absent') {
                try {
                    Write-Verbose ('Removing collection <{0}>' -f $Collection)
                    Invoke-Command -Session $Session -ScriptBlock {
                        Write-Verbose ('Removing collection')
                        Remove-RDSessionCollection -ConnectionBroker $Using:RDCB -CollectionName $Using:Collection
                    }
                    Write-Verbose 'Done creating deplyoment without exception'

                } catch {
                    Write-Error ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
                }
            }
        }

        if ((Compare-Object -ReferenceObject $this.SessionHost -DifferenceObject $Configuration['SessionHost']).Count -gt 0) {
            #
        }
    }

    [Bool] Test() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()

        Write-Verbose 'Checking configuration'
        return ($Configuration['Ensure'] = 'Present')
    }

    [cRDSessionCollection] Get() {
        $Configuration = [hashtable]::new()
        $Configuration['Ensure']           = 'Present'
        $Configuration['ConnectionBroker'] = $null
        $Configuration['Name']             = $null
        $Configuration['Description']      = $null
        $Configuration['Credential']       = $null

        Write-Verbose 'Initialized the hash table'

        try {
            Write-Verbose ('Calling cmdlets on connection broker <{0}>' -f $this.ConnectionBroker)
            $RDCB = $this.ConnectionBroker
            $Collection = $this.Name

            Write-Verbose ('Creating session')
            $Session = New-PSSession -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential
            Write-Verbose ('Fetching general properties')
            $Collection = Invoke-Command -Session $Session -ScriptBlock {
                Write-Verbose ('Calling now')
                Get-RDSessionCollectionConfiguration -ConnectionBroker $Using:RDCB -CollectionName $Using:Collection -ErrorAction SilentlyContinue
            }
            Write-Verbose ('Fetching associated session hosts')
            $SessionHosts = Invoke-Command -Session $Session -ScriptBlock {
                Write-Verbose ('Calling now')
                Get-RDSessionHost -ConnectionBroker $Using:RDCB -CollectionName $Using:Collection
            }
            
            Write-Verbose 'Populating hash table'
            $Configuration['Name']         = $Collection.CollectionName
            $Configuration['Description']  = $Collection.CollectionDescription
            $Configuration['SessionHosts'] = $SessionHosts | Select-Object -ExpandProperty SessionHost
            Write-Verbose 'Done populating without exception'

        } catch {
            Write-Error 'Error populating'
        }

        Write-Verbose ('Checking compliance')
        if ($Configuration['Name']        -ine $this.Name)        { $Configuration['Ensure'] = 'Absent' }
        if ($Configuration['Description'] -ine $this.Description) { $Configuration['Ensure'] = 'Absent' }

        if ((Compare-Object -ReferenceObject $this.SessionHost -DifferenceObject $Configuration['SessionHost']).Count -gt 0) {$Configuration['Ensure'] = 'Absent'}

        Write-Verbose ('Returning hash table')
        return $Configuration
    }
}

[DscResource()]
class cRDRemoteApp {
 
    #region Parameters
    [DscProperty(Key)]
    [String]$ConnectionBroker

    [DscProperty(Mandatory)]
    [string]$CollectionName
 
    [DscProperty(Mandatory)]
    [string]$DisplayName
 
    # FileVirtualPath
    [DscProperty(Mandatory)]
    [string]$FilePath

    [DscProperty()]
    [string]$Alias
 
    [DscProperty()]
    [CommandLineSettingValue]$CommandLineSetting

    [DscProperty()]
    [string]$FolderName

    [DscProperty()]
    [string]$IconIndex

    [DscProperty()]
    [string]$IconPath

    [DscProperty()]
    [string]$RequiredCommandLine

    [DscProperty()]
    [bool]$ShowInWebAccess

    [DscProperty()]
    [string[]]$UserGroups
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential
    #endregion

    [Void] Set() {
        #https://technet.microsoft.com/en-us/library/jj215450%28v=wps.630%29.aspx
        #New-RDRemoteApp
    }

    [Bool] Test() {return $false}

    [cRDRemoteApp] Get() {
        $Configuration = [hashtable]::new()
        $Configuration.Add('RDCB', '')
        $Configuration.Add('Ensure',           'Absent')

        return $Configuration
    }
>>>>>>> 40f370576b269867976ef24746033ee713046765
}
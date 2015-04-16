enum Ensure {
   Absent
   Present
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
class cRDSessionDeployment {

    [DscProperty(Key)]
    [String]$ConnectionBroker
 
    [DscProperty(Mandatory)]
    [String]$SessionHost
 
    [DscProperty(Mandatory)]
    [String]$WebAccess
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential

    [Void] Set() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()

        Write-Verbose 'Checking for RDCB role'
        if (-Not $Configuration.ConnectionBroker -icontains $this.ConnectionBroker) {
            Write-Verbose ('Creating new deployment RDCB={0} RDSH={1} RDWA={2}' -f $this.ConnectionBroker, $this.SessionHost, $this.WebAccess)

            $oldToken = $null
            $context  = $null
            $newToken = $null
            try {
                New-RDSessionDeployment -ConnectionBroker $this.ConnectionBroker -SessionHost $this.SessionHost -WebAccessServer $this.WebAccess

                Write-Verbose 'Done creating deplyoment without exception'

            } catch {
                Write-Verbose ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
            }
        }
        <#Write-Verbose 'Checking for RDSH role'
        if (-Not $Configuration.SessionHost      -icontains $this.SessionHost) {
            Write-Verbose 'Adding RDSH server'
            Add-RDServer -ConnectionBroker $this.ConnectionBroker -Server $this.SessionHost -Role RDS-RD-SERVER
        }
        Write-Verbose 'Checking for RDWA role'
        if (-Not $Configuration.WebAccess        -icontains $this.WebAccess) {
            Write-Verbose 'Adding RDWA server'
            Add-RDServer -ConnectionBroker $this.ConnectionBroker -Server $this.WebAccess -Role RDS-WEB-ACCESS
        }#>

        Write-Verbose 'Done'
    }

    [Bool] Test() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()

        Write-Verbose 'Checking for RDCB role'
        if (-Not $Configuration.ConnectionBroker -icontains $this.ConnectionBroker) {
            Write-Verbose 'Returning $false'
            return $false
        }
        <#Write-Verbose 'Checking for RDSH role'
        if (-Not $Configuration.SessionHost      -icontains $this.SessionHost) {
            Write-Verbose 'Returning $false'
            return $false
        }
        Write-Verbose 'Checking for RDWA role'
        if (-Not $Configuration.WebAccess        -icontains $this.WebAccess) {
            Write-Verbose 'Returning $false'
            return $false
        }#>

        Write-Verbose 'All role are present. Returning $true'
        return $true
    }

    [cRDSessionDeployment] Get() {
        $Configuration = [hashtable]::new()
        $Configuration['ConnectionBroker'] = $null
        $Configuration['SessionHost']      = $null
        $Configuration['WebAccess']        = $null

        Write-Verbose 'Initialized the hash table'

        try {
            Write-Verbose 'Calling Get-RDServer'
            $DeploymentRoles = Get-RDServer -ErrorAction SilentlyContinue
            Write-Verbose 'Populating hash table'
            $Configuration['ConnectionBroker'] = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-CONNECTION-BROKER'} | Select-Object -ExpandProperty Server | Get-Fqdn
            $Configuration['SessionHost']      = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-RD-SERVER'}         | Select-Object -ExpandProperty Server | Get-Fqdn
            $Configuration['WebAccess']        = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-WEB-ACCESS'}        | Select-Object -ExpandProperty Server | Get-Fqdn
            Write-Verbose 'Done populating without exception'

        } catch {
            Write-Verbose 'Error populating'
        }

        Write-Verbose 'Returning hash table'
        return $Configuration
    }
}

[DscResource()]
class cRDSHConfiguration {

    [DscProperty(Mandatory)]
    [Ensure]$Ensure
 
    [DscProperty(Key)]
    [String]$RDCB

    [Void] Set() {}

    [Bool] Test() {return $false}

    [cRDSHConfiguration] Get() {
        $Configuration = [hashtable]::new()
        $Configuration.Add('RDCB', '')
        $Configuration.Add('Ensure',           'Absent')

        return $Configuration
    }
}

[DscResource()]
class cRDWAConfiguration {

    [DscProperty(Mandatory)]
    [Ensure]$Ensure
 
    [DscProperty(Key)]
    [String]$RDCB

    [Void] Set() {}

    [Bool] Test() {return $false}

    [cRDWAConfiguration] Get() {
        $Configuration = [hashtable]::new()
        $Configuration.Add('RDCB', '')
        $Configuration.Add('Ensure',           'Absent')

        return $Configuration
    }
}
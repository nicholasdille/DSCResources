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
class cRDSessionHost {

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

        Write-Verbose 'Testing for session host'
        if ($this.Ensure -ieq 'Present' -and $Configuration.Ensure -ieq 'Absent') {
            try {
                $RDCB = $this.ConnectionBroker
                $RDSH = $env:COMPUTERNAME | Get-Fqdn
                Write-Verbose ('Adding session host <{0}> to connection broker <{1}>' -f $RDCB, $RDSH)
                Invoke-Command -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential -ScriptBlock {
                    Write-Verbose ('Extending deployment (RDCB={0} RDSH={1})' -f $Using:RDCB, $Using:RDSH)
                    Add-RDServer -ConnectionBroker $Using:RDCB -Server $Using:RDSH -Role RDS-RD-SERVER
                }

                Write-Verbose 'Done creating deplyoment without exception'

            } catch {
                Write-Verbose ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
            }

        } elseif ($this.Ensure -ieq 'Absent' -and $Configuration.Ensure -ieq 'Present') {
            try {
                $RDCB = $this.ConnectionBroker
                $RDSH = $env:COMPUTERNAME | Get-Fqdn
                Write-Verbose ('Removing session host <{0}> from connection broker <{1}>' -f $RDCB, $RDSH)
                Invoke-Command -ComputerName $env:COMPUTERNAME -Authentication Credssp -Credential $this.Credential -ScriptBlock {
                    Write-Verbose ('Removing session host (RDCB={0} RDSH={1})' -f $Using:RDCB, $Using:RDSH)
                    Remove-RDServer -ConnectionBroker $Using:RDCB -Server $Using:RDSH -Role RDS-RD-SERVER
                }

                Write-Verbose 'Done creating deplyoment without exception'

            } catch {
                Write-Verbose ('Failed to create deployment. Exception: {0}' -f $_.Exception.toString())
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
            $Configuration['SessionHost']      = $DeploymentRoles | Where-Object {$_.Roles -icontains 'RDS-RD-SERVER'}         | Select-Object -ExpandProperty Server | Get-Fqdn
            if ($Configuration['SessionHost'] -icontains ($env:COMPUTERNAME | Get-Fqdn)) {
                $Configuration['Ensure'] = 'Present'
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

    [DscProperty(Key)]
    [string]$ConnectionBroker
 
    [DscProperty(Mandatory)]
    [String]$SessionHost
 
    [DscProperty(Mandatory)]
    [String]$WebAccess
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential

    [Void] Set() {
        Write-Verbose 'Fetching configuration'
        $Configuration = $this.Get()

        if ($Configuration.ConnectionBroker -ne $null) {
            throw ('A RDS deployment is already present (RDCB={0} // RDWA={1} // RDSH={2})' -f ($Configuration.ConnectionBroker -join ','), ($Configuration.WebAccess -join ','), ($Configuration.SessionHost -join ','))
        }

        Write-Verbose 'Checking for quick deployment'
        if ($this.ConnectionBroker -ieq $env:COMPUTERNAME -and
            $this.WebAccess        -ieq $env:COMPUTERNAME -and
            $this.SessionHost      -ieq $env:COMPUTERNAME) {
            Write-Verbose 'Creating new quick deployment'
            New-RDSessionDeployment -ConnectionBroker $env:COMPUTERNAME -SessionHost $env:COMPUTERNAME -WebAccessServer $env:COMPUTERNAME
            Write-Verbose 'Done creating quick deployment'

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

        Write-Verbose 'Checking for RDCB role'
        if ($Configuration.ConnectionBroker -eq $null) {
            Write-Verbose 'No deployment present. Returning $false'
            return $false

        } else {
            Write-Verbose 'Deployment present. Returning $true'
            return $true
        }
    }

    [cRDSessionDeployment] Get() {
        $Configuration = [hashtable]::new()
        $Configuration['Name']             = $null
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

        Write-Verbose ('Current configuration RDCB={0} RDWA={1} RDSH={2}' -f ($Configuration['ConnectionBroker'] -join ','), ($Configuration['WebAccess'] -join ','), ($Configuration['SessionHost'] -join ','))

        Write-Verbose 'Returning hash table'
        return $Configuration
    }
}

[DscResource()]
class cRDSHConfiguration {
 
    [DscProperty(Key)]
    [String]$ConnectionBroker
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential

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
 
    [DscProperty(Key)]
    [String]$ConnectionBroker
 
    [DscProperty(Mandatory)]
    [PSCredential]$Credential

    [Void] Set() {}

    [Bool] Test() {return $false}

    [cRDWAConfiguration] Get() {
        $Configuration = [hashtable]::new()
        $Configuration.Add('RDCB', '')
        $Configuration.Add('Ensure',           'Absent')

        return $Configuration
    }
}
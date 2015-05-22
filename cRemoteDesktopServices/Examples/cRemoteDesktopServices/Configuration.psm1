Configuration RdsSessionDeployment {
    param(
        [string]
        $ConnectionBrokerHost
        ,
        [string]
        $WebAccessHost
        ,
        [string]
        $SessionHost
        ,
        [pscredential]
        $Credential
    )

    Import-DscResource -ModuleName cRemoteDesktopServices

    WindowsFeature RDS-Connection-Broker {
        Name   = 'RDS-Connection-Broker'
        Ensure = 'Present'
    }

    WaitForOne SessionHost {
        Credential       = $Credential
        NodeName         = $SessionHost
        ResourceName     = '[WindowsFeature]RDS-RD-Server'
        RetryCount       = 60
        RetryIntervalSec = 60
        ThrottleLimit    = 5
    }

    WaitForOne WebAccessHost {
        Credential       = $Credential
        NodeName         = $WebAccessHost
        ResourceName     = '[WindowsFeature]RDS-Web-Access'
        RetryCount       = 60
        RetryIntervalSec = 60
        ThrottleLimit    = 5
    }

    cRDSessionDeployment ConnectionBroker {
        ConnectionBroker = $ConnectionBrokerHost
        WebAccess        = $WebAccessHost
        SessionHost      = $SessionHost
        Credential       = $Credential
        DependsOn        = ('[WaitForOne]SessionHost', '[WaitForOne]WebAccessHost', '[WindowsFeature]RDS-Connection-Broker')
    }
}

Configuration RdsRoleWebAccess {
    param(
        [string]
        $ConnectionBrokerHost
        ,
        [pscredential]
        $Credential
    )

    Import-DscResource -ModuleName cRemoteDesktopServices

    WindowsFeature RDS-Web-Access {
        Name   = 'RDS-Web-Access'
        Ensure = 'Present'
    }

    cRDWebAccessHost Deployment {
        Ensure               = 'Present'
        ConnectionBroker     = $ConnectionBroker
        Credential           = $Credential
        DependsOn            = '[WindowsFeature] RDS-Web-Access'
    }


    <#WaitForAll ConnectionBrokerHosts {
        Credential       = $Credential
        NodeName         = $ConnectionBrokerHost
        ResourceName     = '[cRDSessionDeployment]ConnectionBroker'
        RetryCount       = 60
        RetryIntervalSec = 60
        ThrottleLimit    = 5
    }#>

    <#cRDWAConfiguration SessionHost {
        ConnectionBroker = $ConnectionBrokerHost
        Credential       = $Credential
        DependsOn        = '[WaitForAll]ConnectionBrokerHosts'
    }#>
}

Configuration RdsRoleSessionHost {
    param(
        [string]
        $ConnectionBroker
        ,
        [pscredential]
        $Credential
    )

    Import-DscResource -ModuleName cRemoteDesktopServices

    WindowsFeature RDS-RD-Server {
        Name   = 'RDS-RD-Server'
        Ensure = 'Present'
    }

    cRDSessionHost Deployment {
        Ensure               = 'Present'
        ConnectionBroker     = $ConnectionBroker
        Credential           = $Credential
        DependsOn            = '[WindowsFeature]RDS-RD-Server'
    }

    <#WaitForOne ConnectionBrokerHosts {
        Credential       = $Credential
        NodeName         = $ConnectionBroker
        ResourceName     = '[cRDSessionDeployment]ConnectionBroker'
        RetryCount       = 60
        RetryIntervalSec = 60
        ThrottleLimit    = 5
    }#>

    <#cRDSHConfiguration SessionHost {
        ConnectionBroker = $ConnectionBrokerHost
        Credential       = $Credential
        DependsOn        = '[WaitForAll]ConnectionBrokerHosts'
    }#>
}

Configuration RdsQuickSessionDeployment {
    param(
        [string]
        $NodeName
        ,
        [pscredential]
        $Credential
    )

    Import-DscResource -ModuleName cRemoteDesktopServices

    Node $AllNodes.Where{$_.Role -icontains 'All'}.NodeName {

        WindowsFeature FeatureRDCB {
            Name   = 'RDS-Connection-Broker'
            Ensure = 'Present'
        }

        WindowsFeature FeatureRDSH {
            Name   = 'RDS-RD-Server'
            Ensure = 'Present'
        }

        WindowsFeature FeatureRDWA {
            Name   = 'RDS-Web-Access'
            Ensure = 'Present'
        }

        cRDSessionDeployment Deployment {
            ConnectionBroker     = $NodeName
            WebAccess            = $NodeName
            SessionHost          = $NodeName
            Credential           = $Credential
            DependsOn            = '[WindowsFeature]FeatureRDCB', '[WindowsFeature]FeatureRDSH', '[WindowsFeature]FeatureRDWA'
        }

        <#cRDSHConfiguration SessionHost {
            ConnectionBroker = $ConnectionBrokerHost
            Credential       = $Credential
        }#>

        <#cRDWAConfiguration SessionHost {
            ConnectionBroker = $ConnectionBrokerHost
            Credential       = $Credential
        }#>
    }
}

Configuration RdsSessionTestDeployment {
    param(
        [pscredential]
        $Credential
    )

    Import-DscResource -ModuleName cRemoteDesktopServices

    Node $AllNodes.NodeName {

        if ($Node.Role -icontains 'SessionHost') {
            WindowsFeature FeatureRDSH {
                Name   = 'RDS-RD-Server'
                Ensure = 'Present'
            }

            WindowsFeature FeatureRDWA {
                Name   = 'RDS-Web-Access'
                Ensure = 'Present'
            }

            cRDWebAccessHost Deployment {
                Ensure               = 'Absent'
                ConnectionBroker     = $AllNodes.where{$_.Role -icontains 'ConnectionBroker' -or $_.Role -icontains 'All'}.NodeName
                Credential           = $Credential
                DependsOn            = '[WindowsFeature]FeatureRDSH', '[WindowsFeature]FeatureRDWA'
            }
        }
    }
}
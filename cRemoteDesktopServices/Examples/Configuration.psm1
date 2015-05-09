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
    }
}
Configuration RdsSessionDeployment {
    param(
        [pscredential]
        $Credential
    )

    Import-DscResource -ModuleName cRemoteDesktopServices

    Node $AllNodes.Where{$_.Role -icontains 'RdsQuick'}.NodeName {

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
            ConnectionBroker     = $Node.NodeName
            WebAccess            = $Node.NodeName
            SessionHost          = $Node.NodeName
            Credential           = $Credential
            DependsOn            = '[WindowsFeature]FeatureRDCB', '[WindowsFeature]FeatureRDSH', '[WindowsFeature]FeatureRDWA'
        }
    }

    Node $AllNodes.Where{$_.Role -icontains 'ConnectionBroker'}.NodeName {
        
        WindowsFeature FeatureRDCB {
            Name   = 'RDS-Connection-Broker'
            Ensure = 'Present'
        }

        cRDSessionDeployment Deployment {
            ConnectionBroker     = $Node.NodeName
            WebAccess            = $AllNodes.Where{$_.Role -icontains 'WebAccess'}.NodeName
            SessionHost          = $AllNodes.Where{$_.Role -icontains 'SessionHost'}.NodeName
            Credential           = $Credential
            DependsOn            = '[WindowsFeature]FeatureRDCB'
        }
    }

    Node $AllNodes.Where{$_.Role -icontains 'NewSessionHost'}.NodeName {

        WindowsFeature RDS-RD-Server {
            Name   = 'RDS-RD-Server'
            Ensure = 'Present'
        }

        cRDSessionHost Deployment {
            Ensure               = 'Present'
            ConnectionBroker     = $AllNodes.Where{$_.Role -icontains 'ConnectionBroker'}.NodeName
            Credential           = $Credential
            DependsOn            = '[WindowsFeature]RDS-RD-Server'
        }
    }

    Node $AllNodes.Where{$_.Role -icontains 'NewWebAccess'}.NodeName {

        WindowsFeature RDS-Web-Access {
            Name   = 'RDS-Web-Access'
            Ensure = 'Present'
        }

        cRDWebAccessHost Deployment {
            Ensure               = 'Present'
            ConnectionBroker     = $AllNodes.Where{$_.Role -icontains 'ConnectionBroker'}.NodeName
            Credential           = $Credential
            DependsOn            = '[WindowsFeature] RDS-Web-Access'
        }
    }
}
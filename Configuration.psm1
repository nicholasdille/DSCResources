Configuration RemoteDesktopSessionDeployment {
    param(
        [pscredential]
        $Credential
    )

    Import-DscResource -ModuleName cRemoteDesktopServices

    Node $AllNodes.NodeName {

        if ($Node.Role -icontains 'ConnectionBroker') {
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
                ConnectionBroker     = $AllNodes.where{$_.Role -icontains 'ConnectionBroker'}.NodeName
                WebAccess            = $AllNodes.where{$_.Role -icontains 'WebAccess'}.NodeName
                SessionHost          = $AllNodes.where{$_.Role -icontains 'SessionHost'}.NodeName
                Credential           = $Credential
                DependsOn            = '[WindowsFeature]FeatureRDCB', '[WindowsFeature]FeatureRDSH', '[WindowsFeature]FeatureRDWA'
            }
        }
    }
}
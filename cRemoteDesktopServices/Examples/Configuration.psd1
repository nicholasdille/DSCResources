@{
    AllNodes = @(

        @{
            NodeName                    = 'RDS-01.example.com'
            Role                        = ('RdsQuick')
            PSDscAllowPlainTextPassword = $true
        }

        @{
            NodeName                    = 'RDCB-01.example.com'
            Role                        = ('ConnectionBroker')
            PSDscAllowPlainTextPassword = $true
        }

        @{
            NodeName                    = 'RDWA-01.example.com'
            Role                        = ('WebAccess')
            PSDscAllowPlainTextPassword = $true
        }

        @{
            NodeName                    = 'RDSH-01.example.com'
            Role                        = ('SessionHost')
            PSDscAllowPlainTextPassword = $true
        }

        @{
            NodeName                    = 'RDWA-02.example.com'
            Role                        = ('NewWebAccess')
            PSDscAllowPlainTextPassword = $true
        }

        @{
            NodeName                    = 'RDSH-03.example.com'
            Role                        = ('NewSessionHost')
            PSDscAllowPlainTextPassword = $true
        }

    )
}
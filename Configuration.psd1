@{
    AllNodes = @(

        @{
            NodeName                    = 'RDS-01.example.com'
            Role                        = ('ConnectionBroker')
            PSDscAllowPlainTextPassword = $true
        }

        @{
            NodeName                    = 'RDS-02.example.com'
            Role                        = ('SessionHost')
            PSDscAllowPlainTextPassword = $true
        }

    )
}
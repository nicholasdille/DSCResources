@{
    AllNodes = @(

        @{
            NodeName                    = 'RDS-02.demo.dille.name'
            Role                        = ('ConnectionBroker', 'WebAccess', 'SessionHost')
            PSDscAllowPlainTextPassword = $true
        }

    )
}
@{
    AllNodes = @(

        @{
            NodeName                    = 'RDS-01.demo.dille.name'
            Role                        = ('ConnectionBroker')
            PSDscAllowPlainTextPassword = $true
        }

        @{
            NodeName                    = 'RDS-02.demo.dille.name'
            Role                        = ('SessionHost')
            PSDscAllowPlainTextPassword = $true
        }

        <#@{
            NodeName                    = 'RDS-03.demo.dille.name'
            Role                        = 'SessionHost'
            PSDscAllowPlainTextPassword = $true
        }#>

    )
}
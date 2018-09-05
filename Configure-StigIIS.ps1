<# 
.SYNOPSIS 
    Check, remediate, and report IIS 8.5 Server and Site STIG vulnerabilities.

.DESCRIPTION 
    Check, remediate, and report IIS 8.5 Server and Site STIG vulnerabilities.

.NOTES
    Author: JBear
    Date: 9/5/2018

    STIG Release: 2018 Q3
    Not all STIG items are addressed, as some require specific environment information. 
    This will either configure or report the status of the vulnerabilities below and eliminate a major portion of all items needing to be reviewed.
    
    Before proceeding, snapshot any virtual machine you run this on. If you notice that your sites go down, revert the snapshot and comment out sections of the functions at the end of this script.
    You will be able to troubleshoot things pretty quickly like this. There are some functions built below that have had the configuration portion commented out purposesly because that settings broke a portion of the Web Server.
    Feel free to uncomment and test these for yourself, if needed. 

    Reports will be output to the $ServerPath variable; you will need to set this for the desired location.

    Configured/Reported Vulnerabilities: 
    V-76679, V-76779, V-76781, V-76681, V-76783, V-76683, V-76785, V-76685, V-76787, V-76687, V-76689, V-76789, V-76791, V-76695, V-76697, V-76795, V-76701, V-76703, V-76707, V-76719, V-76709, V-76711, V-76797, V-76713, V-76803, 
    V-76715, V-76717, V-76725, V-76727, V-76777, V-76731, V-76733, V-76829, V-76735, V-76737, V-76835, V-76753, V-76755, V-76757, V-76855, V-76759, V-76767, V-76769, V-76771, V-76773, V-76775, V-76813, V-76805, V-76809, V-76851, 
    V-76861, V-76811, V-76817, V-76819, V-76821, V-76823, V-76825, V-76827, V-76831, V-76837, V-76839, V-76841, V-76859, V-76867, V-76869, V-76871, V-76873, V-76875, V-76877, V-76879, V-76881, V-76883

    Require Manual Checks:
    V-76719, (V-76695, V-76697, V-76795), (V-76701, V-76751), V-76707, V-76745
#>

param(

    [Parameter(ValueFromPipeline=$true)]
    [String[]]$Computername = $env:COMPUTERNAME,

    [Parameter(ValueFromPipeline=$true)]
    [String] $ServerPath = "$([Environment]::GetFolderPath("MyDocuments"))\IIS\$Computername"
)

if(!(Test-Path $ServerPath)) {

    New-Item -ItemType Directory $ServerPath -Force
}

Try {
    
    Import-Module WebAdministration
}

Catch {
    
    Write-Host "Unable to load WebAdministration module."
    Break
}

function V-76759 {
<#
.SYNOPSIS 
    Check, configure, and verify SSL/TLS registry keys for vulnerability 76759.

.DESCRIPTION
    Check, configure, and verify SSL/TLS registry keys for vulnerability 76759.
#>

    param (

        #TLS registry keys
        [String[]]$RegKeys0 = @(
    
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
        ),

        #SSL registry keys
        [String[]]$RegKeys1 = @(
    
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 1.0\Server',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
        ),
    
        #STIG required key name 
        [Parameter(Dontshow)]
        [String]$SubKeyName = 'DisabledByDefault'
    )

    foreach($Key0 in $RegKeys0) {

        $STIGValue0 = '0'        

        #If key doesn't exist, create key
        if(!(Test-Path $Key0)) {
            
            New-Item $Key0 -Force | Out-Null
        }
            
        #Create STIG required key property and set proper value
        if((Get-ItemProperty $Key0).DisabledByDefault -ne "0") {
                
            New-ItemProperty $Key0 -Name $SubKeyName -PropertyType DWORD -Value $STIGValue0 -ErrorAction SilentlyContinue -Force | Out-Null 
        }
        
        #Get current key property values
        $KeyValue0 = (Get-ItemProperty $Key0).DisabledByDefault
        $ValueType0 = (Get-Item $Key0).GetValueKind("DisabledByDefault")

        #Check compliance of each key according to STIG
        $Compliant0 = @(

            if($ValueType0 -eq "DWORD") {

                if($KeyValue0 -eq $STIGValue0) {

                    "Yes"
                }

                else {
                
                    "No"
                }
            }

            else {
            
                "No - Incorrect Value Type"
            }
        )

        [PSCustomObject] @{
        
            Vulnerability = 'V-76759'
            Computername = $env:COMPUTERNAME
            Key = $Key0
            KeyPropertyName = $SubKeyName
            ValueType = $ValueType0
            KeyValue = $KeyValue0
            STIGValue = $STIGValue0
            Compliant = "$Compliant0"
        }
    }

    foreach($Key1 in $RegKeys1) {

        $STIGValue1 = '1'

        #If key doesn't exist, create key
        if(!(Test-Path $Key1)) {
            
            New-Item $Key1 -Force | Out-Null
        }
            
        #Create STIG required key property and set proper value
        if((Get-ItemProperty $Key1).DisabledByDefault -ne "1") {
      
            New-ItemProperty $Key1 -Name $SubKeyName -PropertyType DWORD -Value $STIGValue1 -ErrorAction SilentlyContinue -Force | Out-Null 
        }

        #Get current key property values
        $KeyValue1 = (Get-ItemProperty $Key1).DisabledByDefault
        $ValueType1 = (Get-Item $Key1).GetValueKind("DisabledByDefault")

        #Check compliance of each key according to STIG
        $Compliant1 = @(

            if($ValueType1 -eq "DWORD") {

                if($KeyValue1 -eq $STIGValue1) {

                    "Yes"
                }

                else {
                
                    "No"
                }
            }

            else {
            
                "No - Incorrect Value Type"
            }
        )

        [PSCustomObject] @{
        
            Vulnerability = 'V-76759'
            Computername = $env:COMPUTERNAME
            Key = $Key1
            KeyPropertyName = $SubKeyName
            ValueType = $ValueType1
            KeyValue = $KeyValue1
            STIGValue = $STIGValue1
            Compliant = "$Compliant1"
        }
    }
}

function V-76707-76719 {
<#
.SYNOPSIS 
    Check baseline account/security group accesses for vulnerability 76707 & 76719.

.DESCRIPTION
    Check baseline account/security group accesses for vulnerability 76707 & 76719.
#>

    #Get Local administrators and groups
    $LocalGroups = net localgroup | where {$_ -notmatch "command completed successfully" -or $_ -notmatch ''} | select -Skip 6 | ForEach-Object {$_.Replace('*','')}
    $LocalAdmin = net localgroup Administrators | where {$_ -notmatch "command completed successfully"} | select -Skip 6

    foreach($LA in $LocalAdmin) {

        if(!([String]::IsNullOrWhiteSpace($LA))) {
            
            [PSCustomObject] @{
                        
                Vulnerability = "V-76707, V-76719"
                Computername = $env:COMPUTERNAME
                AccessType = 'Local Administrator'
                User = $LA
                SecurityGroup = ''
                ObjectClass = ''
                DistinguishedName = 'N/A'
            }
        }
    }

    foreach($LG in $LocalGroups) {
            
        if(!([String]::IsNullOrWhiteSpace($LG))) {
                
            try {
                        
                #Get group members of Security Groups
                $Members = Get-ADGroupMember $LG -ErrorAction Stop
            }

            catch {
                    
                $Members = @()
            }
                 
            foreach($Member in $Members) {

                if(!([String]::IsNullOrWhiteSpace($Member))) {

                    [PSCustomObject] @{
                                
                        Vulnerability = "V-76707, V-76719"
                        Computername = $env:COMPUTERNAME
                        AccessType = 'Group Membership'
                        User = $Member.SamAccountName  
                        SecurityGroup = $LG
                        ObjectClass = $Member.objectClass.ToUpper()
                        DistinguishedName = $Member.DistinguishedName              
                    }
                }   
            }
        }
    }
}

function V-76681-76783 {
<#
.SYNOPSIS
    Add STIG required data fields to the logging feature, including currently active fields for vulnerability 76681 & 76783.

.DESCRIPTION
    Add STIG required data fields to the logging feature, including currently active fields for vulnerability 76681 & 76783.
#>
        
    #STIG required log fields
    $RequiredFields = @(
            
        "Date",
        "Time",
        "ClientIP",
        "UserName",
        "Method",
        "UriQuery",
        "HttpStatus",
        "Referer"
    )

    #Current log fields
    $CurrentFields = (Get-WebConfiguration -Filter System.Applicationhost/Sites/SiteDefaults/logfile).LogExtFileFlags.Split(",")

    #Combine STIG fields and current fields (to ensure nothing is turned off, only turned on)
    [String[]]$Collection = @(
            
        $RequiredFields
        $CurrentFields
    )

    [String]$CollectionString = ($Collection | Select -Unique)

    $Replace = $CollectionString.Replace(' ',",")

    #Set all necessary log fields
    Set-WebConfigurationProperty -Filter 'System.Applicationhost/Sites/SiteDefaults/logfile' -Name 'LogExtFileFlags' -Value $Replace

    #All fields presented after new properties have been set
    $PostFields = (Get-WebConfiguration -Filter System.Applicationhost/Sites/SiteDefaults/logfile).LogExtFileFlags.Split(",")

    [PSCustomObject] @{
        
        Vulnerability = 'V-76681, V-76783'
        PreConfigFields = "$CurrentFields"
        Date = ($PostFields -contains "Date")
        Time = ($PostFields -contains "Time")
        ClientIP = ($PostFields -contains "ClientIP")
        UserName = ($PostFields -contains "UserName")
        Method = ($PostFields -contains "Method")
        URIQuery = ($PostFields -contains "UriQuery")
        ProtocolStatus = ($PostFields -contains "HTTPstatus")
        Referer = ($PostFields -contains "Referer")
        PostConfigurationFields = "$PostFields"
        Compliant = if($PostFields -contains "Date" -and $PostFields -contains "Time" -and $PostFields -contains "ClientIP" -and $PostFields -contains "UserName" -and $PostFields -contains "Method" -and $PostFields -contains "UriQuery" -and $PostFields -contains "HTTPstatus" -and $PostFields -contains "Referer") {

            "Yes"
        }

        else {

            "No"
        }
    }
}

function V-76683-76785 {
<#
.SYNOPSIS 
    Check, configure, and verify baseline logging setting for vulnerability 76683 & 76785.

.DESCRIPTION
    Check, configure, and verify baseline logging setting for vulnerability 76683 & 76785.
#>

    param(
            
        [Parameter(DontShow)]
        [String]$WebPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        [String]$FilterPath = "system.applicationHost/sites/sitedefaults/logfile",

        [Parameter(DontShow)]
        [String]$LogTarget = "logTargetW3C",

        [Parameter(DontShow)]
        [String]$LogValues = "File,ETW"
    )

    #Get pre-configuration values
    $PreWeb = Get-WebConfigurationProperty -PSPath $WebPath -Filter $FilterPath -Name $LogTarget 
    $PreWeb = $PreWeb.Split(",")

    #Output which radio buttons are set
    $PreWeb = @(
            
        if($PreWeb -notcontains "ETW") {
                    
            "Log File Only"
        }

        elseif($PreWeb -notcontains "File") {
                
            "ETW Event Only"
        }

        else {
                
            "Both log file and ETW Event"
        }
    )
                
    #Set Logging options to log file and ETW events (both)
    Set-WebConfigurationProperty -PSPath $WebPath -Filter $FilterPath -Name $LogTarget -Value $LogValues

    Start-Sleep -Seconds 2
    #Get pre-configuration values
    $PostWeb = Get-WebConfigurationProperty -PSPath $WebPath -Filter $FilterPath -Name $LogTarget
    $PostWeb = $PostWeb.Split(",")

    #Output which radio buttons are set
    $PostWeb = @(
            
        if($PostWeb -notcontains "ETW") {
                    
            "Log File Only"
        }

        elseif($PostWeb -notcontains "File") {
                
            "ETW Event Only"
        }

        else {
                
            "Both log file and ETW Event"
        }
    )

    [PSCustomObject] @{
            
        Vulnerability = 'V-76683, V-76785'
        PreConfig = "$PreWeb"
        PostConfiguration = "$PostWeb"
        Compliant = if($PostWeb -eq "Both log file and ETW Event") {
                
            "Yes"
        } 
                
        else { 
                
            "No"
        }
    }
}

function V-76685-76787 {
<#
.SYNOPSIS 
    Check, configure, and verify baseline logging setting for vulnerability 76683 & 76787.

.DESCRIPTION
    Check, configure, and verify baseline logging setting for vulnerability 76683 & 76787.
#>
        
    param(
            
        #Default log directory
        [Parameter(DontShow)]
        $LogFilePath = 'C:\inetpub\logs\LogFiles\W3SVC2',

        #Get non-loopback IP address
        [Parameter(DontShow)]
        $WebIP = (Get-NetIPAddress | Where { $_.InterfaceAlias -notlike "*Loopback*"}).IPAddress
    )
            
    #Retrieve most recent log file
    $CurrentLog = Get-ChildItem $LogFilePath -Force | Sort LastWriteTime -Descending | Select -First 1
            
    #Parse log files for data
    $LogTail = Get-Content -Path "$LogFilePath\$($CurrentLog.Name)" -Tail 200 -Force

    foreach($Tail in $LogTail) {

        [PSCustomObject] @{
            
            Date = $Tail.Split(' ')[0]
            Time = $Tail.Split(' ')[1]
            WebServerIP = $WebIP
            SourceIP = $Tail.Split(' ')[2]
            Method = $Tail.Split(' ')[3]
            URIStem =$Tail.Split(' ')[4]
            URIQuery = $Tail.Split(' ')[5]
            SourcePort =$Tail.Split(' ')[6]
            UserName = $Tail.Split(' ')[7]
            ClientIP = $Tail.Split(' ')[8]
            UserAgent = $Tail.Split(' ')[9]
            Referer = $Tail.Split(' ')[10]
            HTTPstatus = $Tail.Split(' ')[11]
            HTTPSstatus = $Tail.Split(' ')[12]
            Win32status = $Tail.Split(' ')[13]
            TimeTaken = $Tail.Split(' ')[14]
            Compliant = if($WebIP -match $Tail.Split(' ')[2]) {

                "Yes"
            }

            else {
                    
                "No"
            }
        }
    }
}

function V-76687-76689-76789-76791 {
<#
.SYNOPSIS 
    Check, configure, and verify Custom Logging Fields for vulnerabilities 76687, 76689, 76789, & 76791.

.DESCRIPTION
    Check, configure, and verify Custom Logging Fields for vulnerabilities 76687, 76689, 76789, & 76791.
#>
            
    #Custom logging fields
    $Connection = [PSCustomObject] @{
            
        LogFieldName = 'Connection'
        SourceType = 'RequestHeader'
        SourceName = 'Connection'
    }

    $Warning = [PSCustomObject] @{
            
        LogFieldName = 'Warning'
        SourceType = 'RequestHeader'
        SourceName = 'Warning'
    }

    $HTTPConnection = [PSCustomObject] @{
            
        LogFieldName = 'HTTPConnection'
        SourceType = 'ServerVariable'
        SourceName = 'HTTPConnection'
    }

    $UserAgent = [PSCustomObject] @{
            
        LogFieldName = 'User-Agent'
        SourceType = 'RequestHeader'
        SourceName = 'User-Agent'
    }

    $ContentType = [PSCustomObject] @{
            
        LogFieldName = 'Content-Type'
        SourceType = 'RequestHeader'
        SourceName = 'Content-Type'
    }

    $HTTPUserAgent = [PSCustomObject] @{
            
        LogFieldName = 'HTTP_USER_AGENT'
        SourceType = 'ServerVariable'
        SourceName = 'HTTP_USER_AGENT'
    }

    $CustomFields = @(
            
        $Connection,
        $Warning,
        $HTTPConnection,
        $UserAgent,
        $ContentType,
        $HTTPUserAgent
    )

    #All website names
    $WebNames = (Get-Website).Name

    foreach($Custom in $CustomFields) {

        foreach($WebName in $WebNames) {
            
            try {

                #Set custom logging fields
                New-ItemProperty "IIS:\Sites\$($WebName)" -Name "logfile.customFields.collection" -Value $Custom -ErrorAction Stop
            }

            catch {
                
                #Silence duplication errors
            }
        }
    }

    foreach($WebName in $WebNames) {

        #Post-Configuration custom fields
        $PostConfig = (Get-ItemProperty "IIS:\Sites\$($WebName)" -Name "logfile.customFields.collection")

        [PSCustomObject] @{
            
            Vulnerability = "V-76687, V-76689, V-76789, V-76791"
            SiteName = $WebName 
            CustomFields = $($PostConfig.logFieldName)
            Compliant = if($PostConfig.logFieldName -contains "Connection" -and $PostConfig.logFieldName -contains "Warning" -and $PostConfig.logFieldName -contains "HTTPConnection" -and $PostConfig.logFieldName -contains "User-Agent" -and $PostConfig.logFieldName -contains "Content-Type" -and $PostConfig.logFieldName -contains "HTTP_USER_AGENT") {
                
                "Yes"
            }

            else {
                
                "No"
            }
        }
    }
}

function V-76679-76779-76781 {
<#
.SYNOPSIS 
    Check, configure, and verify site SSL settings for vulnerability 76679, 76779, & 76781.

.DESCRIPTION
    Check, configure, and verify site SSL settings for vulnerability 76679, 76779, & 76781.
#>

    param(
                
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name
    )
            
    foreach($Webname in $WebNames) {    
                
        #Pre-configuration SSL values
        $PreFlags = Get-WebConfigurationProperty -Location $Webname -Filter 'system.webserver/security/access' -Name SSLFlags

        if($PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $PreFlags -ne "Ssl,SslNegotiateCert") {
                
            #Set SSL requirements
            Set-WebConfiguration -Location $Webname -Filter 'system.webserver/security/access' -Value 'Ssl,SslNegotiateCert'
        }

        #Post-configuration SSL values
        $PostFlags = Get-WebConfigurationProperty -Location $Webname -Filter 'system.webserver/security/access' -Name SSLFlags

        #Pre-configuration data results
        $PreConfig = @(
                
                
            if($PreFlags -eq 'Ssl' ) {
                
                "SSL: Required | Client Certificates: Ignore"
            }

            elseif($PreFlags -eq 'Ssl,SslNegotiateCert' ) {
                
                "SSL: Required | Client Certificates: Accept"
            }

            elseif($PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert' ) {
                
                "SSL: Required | Client Certificates: Require"
            }

            elseif($PreFlags -eq 'SslNegotiateCert' ) {
                
                "SSL: Not Required | Client Certificates: Accept"
            }

            elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert' ) {
                
                "SSL: Not Required | Client Certificates: Require"
            }

            else {
                    
                "SSL: Not Required | Client Certificates: Ignore"
            }
        )

        #Post-configuration data results
        $PostConfig = @(
                
                
            if($PostFlags -eq 'Ssl' ) {
                
                "SSL: Required | Client Certificates: Ignore"
            }

            elseif($PostFlags -eq 'Ssl,SslNegotiateCert' ) {
                
                "SSL: Required | Client Certificates: Accept"
            }

            elseif($PostFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert' ) {
                
                "SSL: Required | Client Certificates: Require"
            }

            elseif($PostFlags -eq 'SslNegotiateCert' ) {
                
                "SSL: Not Required | Client Certificates: Accept"
            }

            elseif($PostFlags -eq 'SslNegotiateCert,SslRequireCert' ) {
                
                "SSL: Not Required | Client Certificates: Require"
            }

            else {
                    
                "SSL: Not Required | Client Certificates: Ignore"
            }
        )

        #Check SSL setting compliance
        $Compliant = @(
                
            if($PostConfig -eq "SSL: Required | Client Certificates: Accept") {
                    
                "Yes"
            }

            elseif($PostConfig -eq "SSL: Required | Client Certificates: Require") {
                    
                "Yes"
            }

            else {
                    
                "No"
            }
        )
                
        [PSCustomObject] @{
                
            Vulnerability = "V-76679, V-76779, V-76781"
            SiteName = $Webname
            PreConfigFlags = "$PreConfig"
            PostConfigurationFlags = "$PostConfig"
            Compliant = "$Compliant"
        }  
    }
}

function V-76695-76697-76795 {
<#
.SYNOPSIS 
    Report log file ACL settings for vulnerabilities 76695, 76697, & 76795. Needs to be assessed manually.

.DESCRIPTION
    Report log file ACL settings for vulnerabilities 76695, 76697, & 76795. Needs to be assessed manually.
#>

    param(
            
        [Parameter(DontShow)]
        [String]$WebPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        [String]$LogDirectory = (Get-WebConfigurationProperty -PSPath $WebPath -Filter "system.applicationHost/sites/sitedefaults/logfile" -Name Directory).Value.Replace('%SystemDrive%',"$env:SystemDrive")
    )

    #Child directories of IIS log directory
    $LogDirectoryChildren = (Get-ChildItem -Path $LogDirectory -Directory -Recurse -Force)

    foreach($LDC in $LogDirectoryChildren) {

        #Get permissions for each user/security group
        $ACL = (Get-Acl -Path $LDC.FullName).Access

        foreach($Access in $ACL) {
            
            [PSCustomObject] @{
                
                Directory = $LDC.FullName
                'User/Group' = $Access.IdentityReference
                Permissions = $Access.FileSystemRights
                Inherited = $Access.IsInherited
            }
        }
    }
}

function V-76701 {
<#
.SYNOPSIS 
    Report installed software for vulnerability 76701. Needs to be assessed manually.

.DESCRIPTION
    Report installed software for vulnerability 76701. Needs to be assessed manually.
#>
        
    if($PSVersionTable.PSVersion -ge "5.0") {
            
        Get-Package
    }

    else {
  
    $Keys = '','\Wow6432Node'

        foreach ($Key in $keys) {

            try {

                $Apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
            } 
            
            catch {

                Continue
            }

            foreach ($App in $Apps) {

                $Program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                $Name = $Program.GetValue('DisplayName')

                if ($Name -and $Name -match $NameRegex) {

                    [PSCustomObject]@{

                        Computername = $Computer
                        Software = $Name
                        Version = $Program.GetValue('DisplayVersion')
                        Publisher = $Program.GetValue('Publisher')
                        InstallDate = $Program.GetValue('InstallDate')
                        UninstallString = $Program.GetValue('UninstallString')
                        Bits = $(if ($Key -eq '\Wow6432Node') {'64'} else {'32'})
                        Path = $Program.name
                    }
                }
            }
        }              
    }
}

function V-76703 {
<#
.SYNOPSIS 
    Disable proxy settings for Application Request Routing feature for vulnerability 76703.

.DESCRIPTION
    Disable proxy settings for Application Request Routing feature for vulnerability 76703.
#>

    param(
            
        [Parameter(DontShow)]
        [String]$WebPath = 'MACHINE/WEBROOT/APPHOST',
                
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name
    )

    foreach($Webname in $WebNames) {

        try {

            #Disable proxy for Application Request Routing
            Set-WebConfigurationProperty -Location $WebPath -Filter "system.webServer/proxy" -Name "Enabled" -Value "False"

            $ProxyValue = Get-WebConfigurationProperty -PSPath $WebPath -Filter "system.webServer/proxy" -Name "Enabled"

            [PSCustomObject] @{
                
                Vulnerability = "V-76703"
                Computername = $env:COMPUTERNAME
                PostConfigurationProxy = $ProxyValue
            }
        }

        catch {
            
            [PSCustomObject] @{
                
                Vulnerability = "V-76703"
                Computername = $env:COMPUTERNAME
                PostConfigurationProxy = "N/A: Application Request Routing not available"
            }
        }
    }
}

function V-76709 {
<#
.SYNOPSIS 
    Report installed Windows Features for vulnerability 76709.

.DESCRIPTION
    Report installed Windows Features for vulnerability 76709.
#>
            
    #Get all installed Windows Features
    $Features = Get-WindowsFeature | Where {$_.InstallState -eq 'Installed' -or $_.InstallState -eq 'InstallPending'}

    foreach($Feature in $Features) {

        [PSCustomObject] @{
            
            Computername = $env:COMPUTERNAME
            Name = $Feature.Name
            InstallState = $Feature.InstallState
        }
    }
}

function V-76711-76797 {
<#
.SYNOPSIS 
    Remove required MIME mappings for vulnerability 76711 & 76797.

.DESCRIPTION
    Remove required MIME mappings for vulnerability 76711 & 76797.
#>
        
    #Pre-Configuration MIME map collection
    $PreMimeConfig = (Get-WebConfiguration //staticcontent).Collection

    #Adjusted MIM map collection
    $NewCollection = ($PreMimeConfig | where {$_.fileextension -ne '.exe' -and $_.fileextension -ne '.dll' -and $_.fileextension -ne '.com' -and $_.fileextension -ne '.bat' -and $_.fileextension -ne '.csh'})

    #Set new configurations
    Set-WebConfigurationProperty //staticContent -Name Collection -InputObject $NewCollection

    $PostMimeConfig = (Get-WebConfiguration //staticcontent).Collection

    [PSCustomObject] @{
            
        Vulnerability = 'V-76711, V-76797'
        Computername = $env:COMPUTERNAME
        PreConfigExtenstions = $PreMimeConfig.FileExtension
        PreConfigCount = $PreMimeConfig.Count
        PostConfigurationExtenstions = $PostMimeConfig.FileExtension
        PostConfigurationCount = $PostMimeConfig.Count
    }
}

function V-76713-76803 {
<#
.SYNOPSIS 
    Remove Windows feature Web-DAV-Publishing for vulnerability 76713 & 76803.

.DESCRIPTION
    Remove Windows feature Web-DAV-Publishing for vulnerability 76713 & 76803.
#>

    param(
        
        $DAVFeature = 'Web-DAV-Publishing'
    )
        
    #Remove Web-DAV-Publishing feature
    $RemoveFeature = Remove-WindowsFeature -Name $DAVFeature

    [PSCustomObject] @{
            
        Vulnerability = 'V-76713, V-76803'
        Computername = $env:COMPUTERNAME
        FeatureName = $DAVFeature
        RemovedFeatures = $RemoveFeature.FeatureResult
        ExitCode = $RemoveFeature.ExitCode
        RestartNeeded = $RemoveFeature.RestartNeeded
        Compliant = if($RemoveFeature.Success -eq $true) {
                
            "Yes"
        }

        else {
                
            "No"
        }
    }
}

function V-76715 {
<#
.SYNOPSIS 
    Report certificates for vulnerability 76713.

.DESCRIPTION
    Report certificates for vulnerability 76713.
#>

    param(
            
        [Parameter(ValuefromPipeline=$true)]
        [String]$Server = $env:COMPUTERNAME
    )

    $RO = [System.Security.Cryptography.X509Certificates.OpenFlags]"ReadOnly"
    $LM = [System.Security.Cryptography.X509Certificates.StoreLocation]"LocalMachine"

    $Stores = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\root",$LM)
    $Stores.Open($RO)
    $Certs = $Stores.Certificates

    foreach($Cert in $Certs) {
            
        [PSCustomObject] @{
                
            Server = $Server
            DNS = $Cert.DNSNameList
            ExpirationDate = $Cert.NotAfter
            Version = $Cert.Version
            HasPrivateKey = $Cert.HasPrivateKey
        }
    }
}

function V-76717 {
<#
.SYNOPSIS 
    Remove all *.jpp,*.java files for vulnerability 76717.

.DESCRIPTION
    Remove all *.jpp,*.java files for vulnerability 76717.
#>

    $JavaFiles = Get-ChildItem -Path $env:SystemDrive -File -Include *.jpp,*.java -Recurse -Force -ErrorAction SilentlyContinue
            
    if($JavaFiles) {

        $JavaFiles | Remove-Item -Force
        $PostFiles = Get-ChildItem -Path $env:SystemDrive -File -Include *.jpp,*.java -Recurse -Force -ErrorAction SilentlyContinue

        [PSCustomObject] @{

            Vulnerability = 'V-76717'
            Computername = $env:COMPUTERNAME
            FilesRemoved = $JavaFiles
            Compliant = if(!($PostFiles)) {
                        
                "Yes: Files found and removed"
            }

            else {
                    
                "No: File removal incomplete"
            }
        }
    }

    else {
            
        [PSCustomObject] @{
                
            Vulnerability = 'V-76717'
            Computername = $env:COMPUTERNAME
            FilesToRemove = "No files found"
            Compliant = "Yes"
        }
    }
}

function V-76725-76727-76777 {
<#
.SYNOPSIS 
    Configure and verify cookieLess & regenerateExpiredSessionID properties for vulnerability 76725, 76727, & 76777.

.DESCRIPTION
    Configure and verify cookieLess & regenerateExpiredSessionID properties for vulnerability 76725, 76727, & 76777.
#>

    param(
                
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,
                
        [Parameter(DontShow)]
        $FilterPath = 'system.web/sessionState'
    )

    foreach($WebName in $WebNames) {
            
        $PreCookieConfig = Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name CookieLess
        $PreSessionConfig = Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name RegenerateExpiredSessionID
        $PreTimeoutConfig = Get-WebConfigurationProperty -Location $WebName -Filter "/system.webserver/asp/session" -Name Timeout

        Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name CookieLess -Value 'UseCookies'
        Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name RegenerateExpiredSessionID -Value 'True'
        Set-WebConfigurationProperty -Location $Webname -Filter 'system.webServer/asp/session' -Name TimeOut -Value '00:20:00'

        $PostCookieConfig = Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name CookieLess
        $PostSessionConfig = Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name RegenerateExpiredSessionID
        $PostTimeoutConfig = Get-WebConfigurationProperty -Location $WebName -Filter "/system.webserver/asp/session" -Name Timeout

        [PSCustomObject] @{
                
            Vulnerability = "V-76725, V-76727, V-76777"
            Computername = $env:COMPUTERNAME
            SiteName = $WebName
            PreConfigCookiesLess = $PreCookieConfig
            PreConfigSessionID = $PreSessionConfig.Value
            PreConfigTimeout = $PreTimeoutConfig.Value
            PostConfigurationCookiesLess = $PostCookieConfig
            PostConfigurationSessionID = $PostSessionConfig.Value
            PostConfigurationTimeout = $PreTimeoutConfig.Value
            Compliant = if($PostCookieConfig -eq 'UseCookies' -and $PostSessionConfig.Value -eq "True" -and $PostTimeoutConfig.Value -eq '00:20:00') {
                    
                "Yes"
            }

            else {
                    
                "No" 
            }
        }
    }
}

function V-76731 {
<#
.SYNOPSIS 
    Configure and verify Validation and Encryption properties for vulnerability 76731.

.DESCRIPTION
    Configure and verify Validation and Encryption properties for vulnerability 76731.
#>
    param(
                
        [Parameter(DontShow)]
        $FilterPath = 'system.web/machineKey'
    )
    
    $PreConfigValidation = Get-WebConfigurationProperty -Filter $FilterPath -Name Validation
    $PreConfigEncryption = Get-WebConfigurationProperty -Filter $FilterPath -Name Decryption

    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter $FilterPath -Name "Validation" -Value "HMACSHA256"
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter $FilterPath -Name "Decryption" -Value "Auto"

    $PostConfigurationValidation = Get-WebConfigurationProperty -Filter $FilterPath -Name Validation
    $PostConfigurationEncryption = Get-WebConfigurationProperty -Filter $FilterPath -Name Decryption

    [PSCustomObject] @{
                
        Vulnerability = "V-76731"
        Computername = $env:COMPUTERNAME
        PreConfigValidation = $PreConfigValidation
        PreConfigEncryption = $PreConfigEncryption.Value
        PostConfigurationValidation = $PostConfigurationValidation
        PostConfigurationEncryption = $PostConfigurationEncryption.Value
        Compliant = if($PostConfigurationValidation -eq 'HMACSHA256' -and $PostConfigurationEncryption.Value -eq 'Auto') {
                    
            "Yes"
        }

        else {
                    
            "No" 
        }
    }
}

function V-76733-76829 {
<#
.SYNOPSIS 
    Configure and verify Directory Browsing properties for vulnerability 76733 & 76829.

.DESCRIPTION
    Configure and verify Directory Browsing properties for vulnerability 76733 & 76829.
#>
    param(
                
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,
                
        [Parameter(DontShow)]
        $FilterPath = 'system.webServer/directoryBrowse'
    )
        
    foreach($WebName in $Webnames) {

        $PreDirectoryBrowsing = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Enabled

        Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name Enabled -Value "False"

        $PostDirectoryBrowsing = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Enabled

        [PSCustomObject] @{
                
            Vulnerability = "V-76829"
            Computername = $env:COMPUTERNAME
            SiteName = $WebName
            PreConfigBrowsingEnabled = $PreDirectoryBrowsing.Value
            PostConfigurationBrowsingEnabled = $PostDirectoryBrowsing.Value
            Compliant = if($PostDirectoryBrowsing.Value -eq $false) {
                    
                "Yes"
            }

            else {
                    
                "No" 
            }
        }
    }

    $PreDirectoryBrowsing = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $FilterPath -Name Enabled

    Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name Enabled -Value "False"

    $PostDirectoryBrowsing = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $FilterPath -Name Enabled

    [PSCustomObject] @{
                
        Vulnerability = "V-76733"
        Computername = $env:COMPUTERNAME
        SiteName = $env:COMPUTERNAME
        PreConfigBrowsingEnabled = $PreDirectoryBrowsing.Value
        PostConfigurationBrowsingEnabled = $PostDirectoryBrowsing.Value
        Compliant = if($PostDirectoryBrowsing.Value -eq $false) {
                    
            "Yes"
        }

        else {
                    
            "No" 
        }
    }
}

function V-76735 {
<#
.SYNOPSIS 
    Configure and verify Indexing configurations for vulnerability 76735.

.DESCRIPTION
    Configure and verify Indexing configurations for vulnerability 76735.
#>
param(

    [Parameter(DontShow)]
    [String] $RegPath = "HKLM:\System\CurrentControlSet\Control\ContentIndex\Catalogs"
)

    if(!(Test-Path $RegPath)) {

        [PSCustomObject] @{
                
            Vulnerability = "V-76735"
            Computername = $env:COMPUTERNAME
            Key = $RegPath
            Compliant = "Not Applicable: Key does not exist"
        }
    }

    else {

        [PSCustomObject] @{
                
            Vulnerability = "V-76735"
            Computername = $env:COMPUTERNAME
            Key = $RegPath
            Compliant = "No: Key exists; check Indexing Service snap-in from MMC console"
        }
        
    }
}


function V-76737-76835 {
<#
.SYNOPSIS 
    Configure and verify Directory Browsing properties for vulnerability 76737 & 76835.

.DESCRIPTION
    Configure and verify Directory Browsing properties for vulnerability 76737 & 76835.
#>
    param(
                
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,
                
        [Parameter(DontShow)]
        $FilterPath = 'system.webServer/httpErrors'
    )
        
    foreach($WebName in $Webnames) {

        $PreErrorMode = Get-WebConfigurationProperty -Filter $FilterPath -Name ErrorMode

        Set-WebConfigurationProperty -Filter $FilterPath -Name ErrorMode -Value "DetailedLocalOnly"

        $PostErrorMode = Get-WebConfigurationProperty -Filter $FilterPath -Name ErrorMode

        [PSCustomObject] @{
                
            Vulnerability = "V-76733, V-76835"
            Computername = $env:COMPUTERNAME
            SiteName = $WebName
            PreConfigBrowsingEnabled = $PreErrorMode
            PostConfigurationBrowsingEnabled = $PostErrorMode
            Compliant = if($PostErrorMode -eq "DetailedLocalOnly") {
                    
                "Yes"
            }

            else {
                    
                "No" 
            }
        }
    }
}

function V-76753 {
<#
.SYNOPSIS 
    Configure and verify Print Services settings for vulnerability 76753.

.DESCRIPTION
    Configure and verify Print Services settings for vulnerability 76753.
#>
    param(
    
        [Parameter(DontShow)]
        [String]$PrintPath = "$($env:windir)\web\printers",

        [Parameter(DontShow)]
        [String[]]$PrintServices = @("Print-Services", "Print-Internet")
    )

    $PrintFeatures = Get-WindowsFeature -Name $PrintServices

    foreach($Feature in $PrintFeatures) {

        [PSCustomObject] @{
                
            Vulnerability = "V-76753"
            Computername = $env:COMPUTERNAME
            Feature = $Feature.Name
            InstallState = $Feature.InstallState
            Compliant = if($Feature.InstallState -eq "Available") {
            
                "Yes"
            }

            else {
                
                "No: Remove $($Feature.Name) Windows Feature"
            }
        }
    }
}

function V-76755 {
<#
.SYNOPSIS 
    Verify URI registry settings for vulnerability 76755.

.DESCRIPTION
    Verify URI registry settings for vulnerability 76755.
#>
    param(
    
        [Parameter(DontShow)]
        [String]$ParameterKey = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters",

        [String[]]$Keys = @(
        
            "URIEnableCache",
            "UriMaxUriBytes",
            "UriScavengerPeriod"
        )
    )

    foreach($Key in $Keys) {

        $KeyCompliant = if(!(Test-Path "$($ParameterKey)\$($Key)")) {
        
            "No: Key does not exist"
        }

        else {
        
            "Yes"
        }

        [PSCustomObject] @{
                
            Vulnerability = "V-76755"
            Computername = $env:COMPUTERNAME
            Key = "$($ParameterKey)\$($Key)"
            Compliant = $KeyCompliant
        }
    }
}


function V-76757-76855 {
<#
.SYNOPSIS 
    Configure and verify Session Security settings for vulnerability 76757 & 76855.

.DESCRIPTION
    Configure and verify Session Security settings for vulnerability 76757 & 76855.
#>
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,
                
        [Parameter(DontShow)]
        $FilterPath = 'system.webServer/asp/session'
    )

    $PreConfigSessionID = Get-WebConfigurationProperty -Filter $FilterPath  -Name KeepSessionIdSecure
    
    Set-WebConfigurationProperty -Filter $FilterPath -Name KeepSessionIdSecure -Value $true

    $PostConfigurationSessionID = Get-WebConfigurationProperty -Filter $FilterPath  -Name KeepSessionIdSecure

    [PSCustomObject] @{
                
        Vulnerability = "V-76757"
        Computername = $env:COMPUTERNAME
        Sitename = $env:COMPUTERNAME
        PreConfigSessionID = $PreConfigSessionID.Value
        PostConfigurationSessionID = $PostConfigurationSessionID.Value
        Compliant = if($PostConfigurationSessionID.Value -eq "True") {
                    
            "Yes"
        }

        else {
                    
            "No" 
        }
    }

    foreach($WebName in $WebName) {

        $PreConfigSessionID = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath  -Name KeepSessionIdSecure
    
        Set-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name KeepSessionIdSecure -Value $true

        $PostConfigurationSessionID = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath  -Name KeepSessionIdSecure

        [PSCustomObject] @{
                
            Vulnerability = "V-76855"
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigSessionID = $PreConfigSessionID.Value
            PostConfigurationSessionID = $PostConfigurationSessionID.Value
            Compliant = if($PostConfigurationSessionID.Value -eq "True") {
                    
                "Yes"
            }

            else {
                    
                "No" 
            }
        }
    }
}

function V-76767 {
<#
.SYNOPSIS 
    Verify File System Component settings for vulnerability 76767.

.DESCRIPTION
    Verify File System Component settings for vulnerability 76767.
#>
    param(
    
        [String] $FSOKey = "HKCR:\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}"
    )

    New-PSDrive -PSProvider Registry -root HKEY_CLASSES_ROOT -Name HKCR | Out-Null

    $ComponentEnabled = if(Test-Path $FSOKey) {
    
        "Enabled"
    }

    else {
    
        "Disabled"
    }

    $Compliant = if(Test-Path $FSOKey) {
        
        "No: Key exists. If component is NOT required for operations, run: regsvr32 scrrun.dll /u to unregister this library. Note: If the File System Object component is required for operations and has supporting documentation signed by the ISSO, this is not a finding."
    }

    else {
        
        "Yes"
    }
    
    [PSCustomObject] @{
        
        Vulnerability = "V-76767"
        Computername = $env:COMPUTERNAME
        Key = $FSOKey
        ComponentStatus = $ComponentEnabled
        Compliant = $Compliant
    }
}

function V-76769 {
<#
.SYNOPSIS 
    Configure and verify CGI and ISAPI module settings for vulnerability 76769.

.DESCRIPTION
    Configure and verify CGI and ISAPI module settings for vulnerability 76769.
#>
    param(
                
        [Parameter(DontShow)]
        $Extensions = @(
        
            "notListedCgisAllowed",
            "notListedIsapisAllowed"
        ),
                
        [Parameter(DontShow)]
        $FilterPath = 'system.webserver/security/isapiCgiRestriction'
    )
    
    $PreConfigCGIExtension = Get-WebConfigurationProperty -Filter $FilterPath -Name "notListedCgisAllowed"
    $PreConfigISAPIExtension = Get-WebConfigurationProperty -Filter $FilterPath -Name "notListedIsapisAllowed"

    Set-WebConfigurationProperty -Filter $FilterPath -Name notListedCgisAllowed -Value "False" -Force
    Set-WebConfigurationProperty -Filter $FilterPath -Name notListedIsapisAllowed -Value "False" -Force

    $PostConfigurationCGIExtension = Get-WebConfigurationProperty -Filter $FilterPath -Name "notListedCgisAllowed"
    $PostConfigurationISAPIExtension = Get-WebConfigurationProperty -Filter $FilterPath -Name "notListedIsapisAllowed"

    [PSCustomObject] @{
                
        Vulnerability = "V-76769"
        Computername = $env:COMPUTERNAME
        PreConfigCGI = $PostConfigurationCGIExtension.Value
        PreConfigISAPI = $PostConfigurationISAPIExtension.Value
        PostConfigurationCGI = $PostConfigurationCGIExtension.Value
        PostConfigurationISAPI = $PostConfigurationISAPIExtension.Value
        Compliant = if($PostConfigurationCGIExtension.Value -eq $false -and $PostConfigurationISAPIExtension.Value -eq $false) {
                    
            "Yes"
        }

        else {
                    
            "No: If auto configuration failed, this section may be locked. Configure manually." 
        }
    }
}

function V-76771 {
<#
.SYNOPSIS 
    Configure and verify Authorization Rules settings for vulnerability 76771.

.DESCRIPTION
    Configure and verify Authorization Rules settings for vulnerability 76771.
#>
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.web/authorization/allow',

        [Parameter(DontShow)]
        [String]$Settings = "[@roles='' and @users='*' and @verbs='']"
    )

    $PreConfigUsers = Get-WebConfigurationProperty -Filter $FilterPath -Name Users

    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter "$($FilterPath)$($Settings)" -Name Users -Value "Administrators"
    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter "system.web/authorization" -Name "." -Value @{users='?'} -Type deny

    $PostConfigurationUsers = Get-WebConfigurationProperty -Filter $FilterPath -Name Users

    [PSCustomObject] @{
                
        Vulnerability = "V-76771"
        Computername = $env:COMPUTERNAME
        PreConfigAuthorizedUsers = $PreConfigUsers.Value
        PostConfigurationAuthorizedUsers = $PostConfigurationUsers.Value
        Compliant = if($PostConfigurationUsers.Value -eq "Administrators") {
                    
            "Yes"
        }

        else {
                    
            "No" 
        }
    }
}

function V-76811 {
<#
.SYNOPSIS 
    Configure and verify Anonymous Authentication settings for vulnerability 76811.

.DESCRIPTION
    Configure and verify Anonymous Authentication settings for vulnerability 76811.
#>
    param(
    
        [Parameter(DontShow)]
        [String]$PSPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webServer/security/authentication/anonymousAuthentication'
    )

    $PreConfigAnonymousAuthentication = Get-WebConfigurationProperty -Filter $FilterPath -Name Enabled

    Set-WebConfigurationProperty -PSPath $PSPath -Filter $FilterPath -Name Enabled -Value "False"

    $PostConfigurationAnonymousAuthentication = Get-WebConfigurationProperty -Filter $FilterPath -Name Enabled
    
    [PSCustomObject] @{
                
        Vulnerability = "V-76811"
        Computername = $env:COMPUTERNAME
        PreConfigAnonymousAuthentication = $PreConfigAnonymousAuthentication.Value
        PostConfigurationAnonymousAuthentication = $PostConfigurationAnonymousAuthentication.Value
        Compliant = if($PostConfigurationAnonymousAuthentication.Value -eq $false) {
                    
            "Yes"
        }

        else {
                    
            "No" 
        }
    }
}

function V-76773 {
<#
.SYNOPSIS 
    Verify Maximum Connection settings for vulnerability 76773.

.DESCRIPTION
    Verify Maximum Connection settings for vulnerability 76773.
#>  
    param(
    
        [Parameter(DontShow)]
        [String]$PSPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.applicationHost/sites/siteDefaults'
    )

    $MaxConnections = Get-WebConfigurationProperty -Filter $FilterPath -Name Limits

    [PSCustomObject] @{

        Vulnerability = "V-76773" 
        Computername = $env:COMPUTERNAME
        MaxConnections = $($MaxConnections.MaxConnections)
        Compliant = if($MaxConnections.MaxConnections -gt 0) {
    
            "Yes"
        }

        else {
        
            "No: Configure MaxConnections attribute higher than 0"
        }
    }
}

function V-76775-76813 {
<#
.SYNOPSIS 
   Configure and verify Session State Mode settings for vulnerability 76775 & 76813.

.DESCRIPTION
   Configure and verify Session State Mode settings for vulnerability 76775 & 76813.
#>  
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.web/sessionState'
    )

    $PreConfigMode = Get-WebConfigurationProperty -Filter $FilterPath -Name Mode

    Set-WebConfigurationProperty -Filter $FilterPath -Name Mode -Value "InProc"

    $PostConfigurationMode = Get-WebConfigurationProperty -Filter $FilterPath -Name Mode

    [PSCustomObject] @{
        
        Vulnerability = "V-76775" 
        Computername = $env:COMPUTERNAME
        Sitename = $env:COMPUTERNAME
        PreConfigMode = $PreConfigMode
        PostConfigurationMode = $PostConfigurationMode
        Compliant = if($PostConfigurationMode -eq "InProc") {
        
            "Yes"
        }

        else {
        
            "No"
        }
    }

    foreach($Webname in $WebNames) {

        $PreConfigMode = Get-WebConfigurationProperty -Filter $FilterPath -Name Mode

        Set-WebConfigurationProperty -Filter $FilterPath -Name Mode -Value "InProc"

        $PostConfigurationMode = Get-WebConfigurationProperty -Filter $FilterPath -Name Mode

        [PSCustomObject] @{
        
            Vulnerability = "V-76813" 
            Computername = $env:COMPUTERNAME
            Sitename = $Webname
            PreConfigMode = $PreConfigMode
            PostConfigurationMode = $PostConfigurationMode
            Compliant = if($PostConfigurationMode -eq "InProc") {
        
                "Yes"
            }

            else {
        
                "No"
            }
        }
    }
}

function V-76805 {
<#
.SYNOPSIS 
   Configure and verify .NET Trust Level settings for vulnerability 76805.

.DESCRIPTION
   Configure and verify .NET Trust Level settings for vulnerability 76805.
#>      
    param(
                
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,
                
        [Parameter(DontShow)]
        $FilterPath = 'system.web/trust'
    )

    foreach($Webname in $WebNames) {

        $PreConfigTrustLevel = (Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name Level).Value

        if($PostConfigTrustLevel -ne "Full" -or $PostConfigTrustLevel -ne "Medium" -or $PostConfigTrustLevel -ne "Low" -or $PostConfigTrustLevel -ne "Minimal") {

            Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name Level -Value "Full"
        }

        $PostConfigTrustLevel = (Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name Level).Value

        [PSCustomObject] @{
        
            Vulnerability = "V-76805" 
            Computername = $env:COMPUTERNAME
            SiteName = $WebName
            PreConfigTrustLevel = $PreConfigTrustLevel
            PostConfigTrustLevel = $PreConfigTrustLevel
            SuggestedTrustLevel = "Full or less"
            Compliant = if($PostConfigTrustLevel -eq "Full" -or $PostConfigTrustLevel -eq "Medium" -or $PostConfigTrustLevel -eq "Low" -or $PostConfigTrustLevel -eq "Minimal") {
        
                "Yes"
            }

            else {
        
                "No"
            }
        }        
    }
}

function V-76809-76851-76861 {
<#
.SYNOPSIS 
    Check, configure, and verify site SSL settings for vulnerability 76809, 76851, & 76861.

.DESCRIPTION
    Check, configure, and verify site SSL settings for vulnerability 76809, 76851, & 76861.

.NOTES
    Setting Client Certificates to Required breaks SolarWinds.
#>

    param(
                
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name
    )
               
    foreach($Webname in $WebNames) {    
                
        #Pre-configuration SSL values for sites
        $PreFlags = Get-WebConfigurationProperty -Location $Webname -Filter 'system.webserver/security/access' -Name SSLFlags

        if($PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $PreFlags -ne "Ssl,SslNegotiateCert" -or $PreFlags -ne "Ssl,SslNegotiateCert,Ssl128" -or $PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {
                
            #Set SSL requirements
            Set-WebConfiguration -Location $Webname -Filter 'system.webserver/security/access' -Value 'Ssl,SslNegotiateCert,Ssl128'
        }

        #Post-configuration SSL values
        $PostFlags = Get-WebConfigurationProperty -Location $Webname -Filter 'system.webserver/security/access' -Name SSLFlags

        #Pre-configuration data results
        $PreConfig = @(
                    
            if($PreFlags -eq 'Ssl' ) {
                
                "SSL: Required | Client Certificates: Ignore"
            }

            elseif($PreFlags -eq 'Ssl,SslNegotiateCert' ) {
                
                "SSL: Required | Client Certificates: Accept"
            }

            elseif($PreFlags -eq 'Ssl,SslRequireCert' ) {
                
                "SSL: Required | Client Certificates: Require"
            }

            elseif($PreFlags -eq 'Ssl,Ssl128' ) {
                
                "SSL: Required | Client Certificates: Ignore | SSL: 128"
            }

            elseif($PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert' ) {
                
                "SSL: Required | Client Certificates: Require"
            }

            elseif($PreFlags -eq 'Ssl,SslNegotiateCert,Ssl128' ) {
                
                "SSL: Required | Client Certificates: Accept | SSL: 128"
            }

            elseif($PreFlags -eq 'Ssl,SslRequireCert,Ssl128' -or $PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert,Ssl128') {
                
                "SSL: Required | Client Certificates: Require | SSL: 128"
            }

            elseif($PreFlags -eq 'SslNegotiateCert' ) {
                
                "SSL: Not Required | Client Certificates: Accept"
            }

            elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert' -or $PreFlags -eq 'SslRequireCert') {
                
                "SSL: Not Required | Client Certificates: Require"
            }

            elseif($PreFlags -eq 'SslRequireCert,Ssl128') {
                
                "SSL: Not Required | Client Certificates: Require | SSL: 128"
            }

            elseif($PreFlags -eq 'SslNegotiateCert,Ssl128' ) {
                
                "SSL: Not Required | Client Certificates: Accept | SSL: 128"
            }

            elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert,Ssl128' ) {
                
                "SSL: Not Required | Client Certificates: Require | SSL: 128"
            }

            elseif($PreFlags -eq 'Ssl128' ) {
                
                "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
            }

            else {
                    
                "SSL: Not Required | Client Certificates: Ignore"
            }
        )

        #Post-configuration data results
        $PostConfig = @(
                
            if($PreFlags -eq 'Ssl' ) {
                
                "SSL: Required | Client Certificates: Ignore"
            }

            elseif($PreFlags -eq 'Ssl,SslNegotiateCert' ) {
                
                "SSL: Required | Client Certificates: Accept"
            }

            elseif($PreFlags -eq 'Ssl,SslRequireCert' ) {
                
                "SSL: Required | Client Certificates: Require"
            }

            elseif($PreFlags -eq 'Ssl,Ssl128' ) {
                
                "SSL: Required | Client Certificates: Ignore | SSL: 128"
            }

            elseif($PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert' ) {
                
                "SSL: Required | Client Certificates: Require"
            }

            elseif($PreFlags -eq 'Ssl,SslNegotiateCert,Ssl128' ) {
                
                "SSL: Required | Client Certificates: Accept | SSL: 128"
            }

            elseif($PreFlags -eq 'Ssl,SslRequireCert,Ssl128' -or $PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert,Ssl128') {
                
                "SSL: Required | Client Certificates: Require | SSL: 128"
            }

            elseif($PreFlags -eq 'SslNegotiateCert' ) {
                
                "SSL: Not Required | Client Certificates: Accept"
            }

            elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert' -or $PreFlags -eq 'SslRequireCert') {
                
                "SSL: Not Required | Client Certificates: Require"
            }

            elseif($PreFlags -eq 'SslRequireCert,Ssl128') {
                
                "SSL: Not Required | Client Certificates: Require | SSL: 128"
            }

            elseif($PreFlags -eq 'SslNegotiateCert,Ssl128' ) {
                
                "SSL: Not Required | Client Certificates: Accept | SSL: 128"
            }

            elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert,Ssl128' ) {
                
                "SSL: Not Required | Client Certificates: Require | SSL: 128"
            }

            elseif($PreFlags -eq 'Ssl128' ) {
                
                "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
            }

            else {
                    
                "SSL: Not Required | Client Certificates: Ignore"
            }
        )

        #Check SSL setting compliance
        $Compliant = @(

            if($PostConfig -eq "SSL: Required | Client Certificates: Require" -or $PostConfig -eq "SSL: Required | Client Certificates: Require | SSL: 128") {
                    
                "Yes"
            }

            else {
                    
                "No: Configuring the Client Certificates settings to Require breaks SolarWinds Web GUI"
            }
        )
                
        [PSCustomObject] @{
                
            Vulnerability = "V-76861"
            Computername = $env:COMPUTERNAME
            SiteName = $Webname
            PreConfigFlags = "$PreConfig"
            PostConfigurationFlags = "$PostConfig"
            Compliant = "$Compliant"
        }  
    }

    #Pre-configuration SSL values for server
    $PreFlags = Get-WebConfigurationProperty -Filter 'system.webserver/security/access' -Name SSLFlags

    if($PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $PreFlags -ne "Ssl,SslNegotiateCert" -or $PreFlags -ne "Ssl,SslNegotiateCert,Ssl128" -or $PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {
                
        #Set SSL requirements
        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/access" -Name SSLFlags -Value 'Ssl,SslNegotiateCert,Ssl128'
    }

    #Post-configuration SSL values
    $PostFlags = Get-WebConfigurationProperty -Filter 'system.webserver/security/access' -Name SSLFlags

    #Pre-configuration data results
    $PreConfig = @(
                    
        if($PreFlags -eq 'Ssl' ) {
                
            "SSL: Required | Client Certificates: Ignore"
        }

        elseif($PreFlags -eq 'Ssl,SslNegotiateCert' ) {
                
            "SSL: Required | Client Certificates: Accept"
        }

        elseif($PreFlags -eq 'Ssl,SslRequireCert' ) {
                
            "SSL: Required | Client Certificates: Require"
        }

        elseif($PreFlags -eq 'Ssl,Ssl128' ) {
                
            "SSL: Required | Client Certificates: Ignore | SSL: 128"
        }

        elseif($PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert' ) {
                
            "SSL: Required | Client Certificates: Require"
        }

        elseif($PreFlags -eq 'Ssl,SslNegotiateCert,Ssl128' ) {
                
            "SSL: Required | Client Certificates: Accept | SSL: 128"
        }

        elseif($PreFlags -eq 'Ssl,SslRequireCert,Ssl128' -or $PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert,Ssl128') {
                
            "SSL: Required | Client Certificates: Require | SSL: 128"
        }

        elseif($PreFlags -eq 'SslNegotiateCert' ) {
                
            "SSL: Not Required | Client Certificates: Accept"
        }

        elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert' -or $PreFlags -eq 'SslRequireCert') {
                
            "SSL: Not Required | Client Certificates: Require"
        }

        elseif($PreFlags -eq 'SslRequireCert,Ssl128') {
                
            "SSL: Not Required | Client Certificates: Require | SSL: 128"
        }

        elseif($PreFlags -eq 'SslNegotiateCert,Ssl128' ) {
                
            "SSL: Not Required | Client Certificates: Accept | SSL: 128"
        }

        elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert,Ssl128' ) {
                
            "SSL: Not Required | Client Certificates: Require | SSL: 128"
        }

        elseif($PreFlags -eq 'Ssl128' ) {
                
            "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
        }

        else {
                    
            "SSL: Not Required | Client Certificates: Ignore"
        }
    )

    #Post-configuration data results
    $PostConfig = @(
                
        if($PreFlags -eq 'Ssl' ) {
                
            "SSL: Required | Client Certificates: Ignore"
        }

        elseif($PreFlags -eq 'Ssl,SslNegotiateCert' ) {
                
            "SSL: Required | Client Certificates: Accept"
        }

        elseif($PreFlags -eq 'Ssl,SslRequireCert' ) {
                
            "SSL: Required | Client Certificates: Require"
        }

        elseif($PreFlags -eq 'Ssl,Ssl128' ) {
                
            "SSL: Required | Client Certificates: Ignore | SSL: 128"
        }

        elseif($PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert' ) {
                
            "SSL: Required | Client Certificates: Require"
        }

        elseif($PreFlags -eq 'Ssl,SslNegotiateCert,Ssl128' ) {
                
            "SSL: Required | Client Certificates: Accept | SSL: 128"
        }

        elseif($PreFlags -eq 'Ssl,SslRequireCert,Ssl128' -or $PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert,Ssl128') {
                
            "SSL: Required | Client Certificates: Require | SSL: 128"
        }

        elseif($PreFlags -eq 'SslNegotiateCert' ) {
                
            "SSL: Not Required | Client Certificates: Accept"
        }

        elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert' -or $PreFlags -eq 'SslRequireCert') {
                
            "SSL: Not Required | Client Certificates: Require"
        }

        elseif($PreFlags -eq 'SslRequireCert,Ssl128') {
                
            "SSL: Not Required | Client Certificates: Require | SSL: 128"
        }

        elseif($PreFlags -eq 'SslNegotiateCert,Ssl128' ) {
                
            "SSL: Not Required | Client Certificates: Accept | SSL: 128"
        }

        elseif($PreFlags -eq 'SslNegotiateCert,SslRequireCert,Ssl128' ) {
                
            "SSL: Not Required | Client Certificates: Require | SSL: 128"
        }

        elseif($PreFlags -eq 'Ssl128' ) {
                
            "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
        }

        else {
                    
            "SSL: Not Required | Client Certificates: Ignore"
        }
    )

    #Check SSL setting compliance
    $Compliant = @(

        if($PostConfig -eq "SSL: Required | Client Certificates: Require" -or $PostConfig -eq "SSL: Required | Client Certificates: Require | SSL: 128") {
                    
            "Yes"
        }

        else {
                    
            "No: Configuring the Client Certificates settings to Require breaks SolarWinds Web GUI"
        }
    )
                
    [PSCustomObject] @{
                
        Vulnerability = "V-76809, V-76851"
        Computername = $env:COMPUTERNAME
        SiteName = $env:COMPUTERNAME
        PreConfigFlags = "$PreConfig"
        PostConfigurationFlags = "$PostConfig"
        Compliant = "$Compliant"
    } 
}

function V-76817 {
<#
.SYNOPSIS 
    Configure and verify URL Request Limit settings for vulnerability 76817.

.DESCRIPTION
    Configure and verify URL Request Limit settings for vulnerability 76817.
#>  
    param(
    
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webServer/security/requestFiltering/requestLimits',

        [Int]$MaxUrl = 4096
    )

    foreach($WebName in $WebNames) {

        $PreConfigMaxUrl = Get-WebConfigurationProperty -Filter $FilterPath -Name MaxUrl

        Set-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name MaxUrl -Value $MaxUrl -Force

        $PostConfigurationMaxUrl = Get-WebConfigurationProperty -Filter $FilterPath -Name MaxUrl

        [PSCustomObject] @{

            Vulnerability = "V-76817" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfiugrationMaxUrl = $PreConfigMaxUrl.Value
            PostConfiugrationMaxUrl = $PostConfigurationMaxUrl.Value
            Compliant = if($PostConfigurationMaxUrl.Value -le $MaxUrl) {
    
                "Yes"
            }

            else {
        
                "No: Value must be $MaxUrl or less"
            }
        }
    }
}

function V-76819 {
<#
.SYNOPSIS 
    Configure and verify Maximum Content Length settings for vulnerability 76819.

.DESCRIPTION
    Configure and verify Maximum Content Length settings for vulnerability 76819.
#>  
    param(
    
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webServer/security/requestFiltering/requestLimits',

        [Int]$MaxContentLength = 30000000
    )

    foreach($WebName in $WebNames) {

        $PreConfigMaxContentLength = Get-WebConfigurationProperty -Filter $FilterPath -Name maxAllowedContentLength

        Set-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name maxAllowedContentLength -Value $MaxContentLength -Force

        $PostConfigurationMaxContentLength = Get-WebConfigurationProperty -Filter $FilterPath -Name maxAllowedContentLength

        [PSCustomObject] @{

            Vulnerability = "V-76819" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfiugrationMaxContentLength = $PreConfigMaxContentLength.Value
            PostConfiugrationMaxContentLength = $PostConfigurationMaxContentLength.Value
            Compliant = if($PostConfigurationMaxContentLength.Value -le $MaxContentLength) {
    
                "Yes"
            }

            else {
        
                "No: Value must be $MaxContentLength or less"
            }
        }
    }
}

function V-76821 {
<#
.SYNOPSIS 
    Configure and verify Maximum Query String settings for vulnerability 76821.

.DESCRIPTION
    Configure and verify Maximum Query String settings for vulnerability 76821.
#>  
    param(
    
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webServer/security/requestFiltering/requestLimits',

        [Int]$MaxQueryString = 2048
    )

    foreach($WebName in $WebNames) {

        $PreConfigMaxQueryString = Get-WebConfigurationProperty -Filter $FilterPath -Name maxQueryString

        Set-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name maxQueryString -Value $MaxQueryString -Force

        $PostConfigurationMaxQueryString = Get-WebConfigurationProperty -Filter $FilterPath -Name maxQueryString

        [PSCustomObject] @{

            Vulnerability = "V-76821" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfiugrationMaxQueryString = $PreConfigMaxQueryString.Value
            PostConfiugrationMaxQueryString = $PostConfigurationMaxQueryString.Value
            Compliant = if($PostConfigurationMaxQueryString.Value -le $MaxQueryString) {
    
                "Yes"
            }

            else {
        
                "No: Value must be $MaxQueryString or less"
            }
        }
    }
}

function V-76823 {
<#
.SYNOPSIS 
    Configure and verify Allow High-Bit Characters settings for vulnerability 76823.

.DESCRIPTION
    Configure and verify Allow High-Bit Characters settings for vulnerability 76823.
#>  
    param(
    
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webServer/security/requestFiltering'
    )

    foreach($WebName in $WebNames) {

        $PreConfigHighBit = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowHighBitCharacters

        Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name "allowHighBitCharacters" -Value "False"

        $PostConfigurationHighBit = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowHighBitCharacters

        [PSCustomObject] @{

            Vulnerability = "V-76823" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigHighBit = $PreConfigHighBit.Value
            PostConfigurationHighBit = $PostConfigurationHighBit.Value
            Compliant = if($PostConfigurationHighBit.Value -eq $false) {
    
                "Yes"
            }

            else {
        
                "No"
            }
        }
    }
}

function V-76825 {
<#
.SYNOPSIS 
    Configure and verify Allow Double Escaping settings for vulnerability 76825.

.DESCRIPTION
    Configure and verify Allow Double Escaping settings for vulnerability 76825.
#>  
    param(
    
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webServer/security/requestFiltering'
    )

    foreach($WebName in $WebNames) {

        $PreConfigDoubleEscaping = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowDoubleEscaping

        Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name allowDoubleEscaping -Value "False"

        $PostConfigurationDoubleEscaping = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowDoubleEscaping

        [PSCustomObject] @{

            Vulnerability = "V-76825" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigDoubleEscaping = $PreConfigDoubleEscaping.Value
            PostConfigurationDoubleEscaping = $PostConfigurationDoubleEscaping.Value
            Compliant = if($PostConfigurationDoubleEscaping.Value -eq $false) {
    
                "Yes"
            }

            else {
        
                "No"
            }
        }
    }
}

function V-76827 {
<#
.SYNOPSIS 
    Configure and verify Allow Unlisted File Extensions settings for vulnerability 76827.

.DESCRIPTION
    Configure and verify Allow Unlisted File Extensions settings for vulnerability 76827.

.NOTES
    Commented out Set-ConfigurationProperty, this setting breaks the Web GUI for SolarWinds. 
#>  
    param(
    
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webServer/security/requestFiltering/fileExtensions'
    )

    foreach($WebName in $WebNames) {

        $PreConfigUnlistedExtensions = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowUnlisted

        #Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name allowUnlisted -Value "False"

        $PostConfigurationUnlistedExtensions = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowUnlisted

        [PSCustomObject] @{

            Vulnerability = "V-76827" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigUnlistedExtensions = $PreConfigUnlistedExtensions.Value
            PostConfigurationUnlistedExtensions = $PostConfigurationUnlistedExtensions.Value
            Compliant = if($PostConfigurationUnlistedExtensions.Value -eq $false) {
    
                "Yes"
            }

            else {
        
                "No: Setting Allow Unlisted File Extensions to False breaks SolarWinds Web GUI"
            }
        }
    }
}

function V-76831 {
<#
.SYNOPSIS 
    Configure and verify Default Document settings for vulnerability 76831.

.DESCRIPTION
    Configure and verify Default Document settings for vulnerability 76831.
#>  
    param(
    
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webServer/defaultDocument'
    )

    foreach($WebName in $WebNames) {

        $PreConfigDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Enabled
        
        if($PreConfigDefaultDocumentEnabled -eq $false) {
        
            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name Enabled -Value "True"
        }

        $PreConfigDefaultDocumentFiles = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Files

        if($PreConfigDefaultDocumentFiles.Count -eq 0) {
        
            Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{value='Default.aspx'}
        }
        
        $PostConfigurationDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Enabled
        $PostConfigurationDefaultDocumentFiles = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Files

        [PSCustomObject] @{
        
            Vulnerability = "V-76831"
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigDefaultDocumentEnabled = $PreConfigDefaultDocumentEnabled.Value
            PreConfigDefaultDocumentFiles = $PreConfigDefaultDocumentFiles.Count
            PostConfigurationDefaultDocumentEnabled = $PostConfigurationDefaultDocumentEnabled.Value
            PostConfigurationDefaultDocumentFiles = $PostConfigurationDefaultDocumentFiles.Count
            Compliant = if($PostConfigurationDefaultDocumentEnabled.Value -eq $true -and $PostConfigurationDefaultDocumentFiles.Count -gt 0) {
            
                "Yes"
            }

            else {
           
                "No" 
            }

        }
    }
}

function V-76837 {
<#
.SYNOPSIS 
    Configure and verify Debug Behavior settings for vulnerability 76837.

.DESCRIPTION
    Configure and verify Debug Behavior settings for vulnerability 76837.
#>  
    param(
    
        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.web/compilation'
    )

    foreach($WebName in $WebNames) {

        $PreConfigDebugBehavior = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Debug

        Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name Debug -Value "False"

        $PostConfigurationDebugBehavior = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Debug

        [PSCustomObject] @{

            Vulnerability = "V-76837" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigDebugBehaviors = $PreConfigDebugBehavior.Value
            PostConfigurationDebugBehavior = $PostConfigurationDebugBehavior.Value
            Compliant = if($PostConfigurationDebugBehavior.Value -eq $false) {
    
                "Yes"
            }

            else {
        
                "No"
            }
        }
    }
}

function V-76839 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Time-Out settings for vulnerability 76839.

.DESCRIPTION
    Configure and verify Application Pool Time-Out settings for vulnerability 76839.
#>  
    param(

        [Parameter(DontShow)]
        [String]$PSPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.applicationHost/applicationPools/applicationPoolDefaults/processModel'
    )

    $PreConfigTimeOut = Get-WebConfigurationProperty -Filter $FilterPath -Name idleTimeOut
        
    if(!([Int]([TimeSpan]$PreConfigTimeOut.Value).TotalMinutes -le 20)) {
        
        Set-WebConfigurationProperty -PSPath $PSPath -Filter $FilterPath -Name idleTimeout -Value "00:20:00"
    }

    $PostConfigTimeOut = Get-WebConfigurationProperty -Filter $FilterPath -Name idleTimeOut

    [PSCustomObject] @{

        Vulnerability = "V-76839" 
        Computername = $env:COMPUTERNAME
        Sitename = $env:COMPUTERNAME
        PreConfigTimeOut = [Int]([TimeSpan]$PreConfigTimeOut.Value).TotalMinutes
        PostConfigTimeOut = [Int]([TimeSpan]$PostConfigTimeOut.Value).TotalMinutes
        Compliant = if([Int]([TimeSpan]$PostConfigTimeOut.Value).TotalMinutes -le 20) {
    
            "Yes"
        }

        else {
       
            "No"
        }
    }
}

function V-76841 {
<#
.SYNOPSIS 
    Configure and verify Session Time-Out settings for vulnerability 76841.

.DESCRIPTION
    Configure and verify Session Time-Out settings for vulnerability 76841.
#>  
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.web/sessionState'
    )

    foreach($WebName in $WebNames) {

        $PreConfigSessionTimeOut = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name TimeOut
        
        if(!([Int]([TimeSpan]$PreConfigSessionTimeOut.Value).TotalMinutes -le 20)) {
        
            Set-WebConfigurationProperty -PSPath $PSPath/$($WebName) -Filter $FilterPath -Name Timeout -Value "00:20:00"
        }

        $PostConfigSessionTimeOut = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name TimeOut

        [PSCustomObject] @{

            Vulnerability = "V-76841" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigSessionTimeOut = [Int]([TimeSpan]$PreConfigSessionTimeOut.Value).TotalMinutes
            PostConfigSessionTimeOut = [Int]([TimeSpan]$PostConfigSessionTimeOut.Value).TotalMinutes
            Compliant = if([Int]([TimeSpan]$PostConfigSessionTimeOut.Value).TotalMinutes -le 20) {
    
                "Yes"
            }

            else {
       
                "No"
            }
        }
    }
}

function V-76859 {
<#
.SYNOPSIS 
    Configure and verify HTTP Cookies and Session Compression settings for vulnerability 76859.

.DESCRIPTION
    Configure and verify HTTP Cookies and Session Compression settings for vulnerability 76859.
#>  
    param(
    
        [Parameter(DontShow)]
        [String]$PSpath = 'MACHINE/WEBROOT',

        [Parameter(DontShow)]
        [String]$FilterPathCookies = 'system.web/httpCookies',

        [Parameter(DontShow)]
        [String]$FilterPathCompression = 'system.web/sessionState'
    )

    $PreConfigCookies = Get-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCookies -Name requireSSL
    $PreConfigCompression = Get-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCompression -Name compressionEnabled

    Set-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCookies -Name requireSSL -Value "True"
    Set-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCompression -Name compressionEnabled -Value "False"

    $PostConfigCookies = Get-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCookies -Name requireSSL
    $PostConfigCompression = Get-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCompression -Name compressionEnabled


    [PSCustomObject] @{

        Vulnerability = "V-76859" 
        Computername = $env:COMPUTERNAME
        Sitename = $env:COMPUTERNAME
        PreConfigCookiesSSL = $PreConfigCookies.Value
        PostConfigCookiesSSL = $PostConfigCookies.Value
        PreConfigCompressionEnabled = $PreConfigCompression.Value
        PostConfigCompressionEnabled = $PostConfigCompression.Value
        Compliant = if($PostConfigCookies.Value -eq $true -and $PostConfigCompression.Value -eq $false) {
    
            "Yes"
        }

        else {
       
            "No"
        }
    }
}

function V-76867 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Recycling settings for vulnerability 76867.

.DESCRIPTION
    Configure and verify Application Pool Recycling settings for vulnerability 76867.
#>  
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'recycling.periodicRestart.requests',

        [Parameter(DontShow)]
        [Int64]$RequestsDefault = 100000
    )

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigRecycle = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath
        
        if($PreConfigRecycle -eq 0) {
        
            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $RequestsDefault
        }

        $PostConfigRecycle = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

        [PSCustomObject] @{

            Vulnerability = "V-76867" 
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigRecycle = $PreConfigRecycle.Value
            PostConfigRecycle = $PostConfigRecycle.Value
            Compliant = if($PostConfigRecycle.Value -gt 0) {
    
                "Yes"
            }

            else {
       
                "No: Value must be set higher than 0"
            }
        }
    }
}

function V-76869 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Virtual Memory Recycling settings for vulnerability 76869.

.DESCRIPTION
    Configure and verify Application Pool Virtual Memory Recycling settings for vulnerability 76869.
#>  
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'recycling.periodicRestart.memory',

        [Parameter(DontShow)]
        [Int64]$VMemoryDefault = 1GB
    )

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigVMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath
        
        if($PreConfigVMemory -eq 0) {
        
            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $VMemoryDefault
        }

        $PostConfigVMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

        [PSCustomObject] @{

            Vulnerability = "V-76869" 
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigVMemory = [String]$PreConfigVMemory.Value
            PostConfigVMemory = [String]$PostConfigVMemory.Value
            Compliant = if($PostConfigVMemory.Value -gt 0) {
    
                "Yes"
            }

            else {
       
                "No: Value must be set higher than 0"
            }
        }
    }
}

function V-76871 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Private Memory Recycling settings for vulnerability 76871.

.DESCRIPTION
    Configure and verify Application Pool Private Memory Recycling settings for vulnerability 76871.
#>  
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'recycling.periodicRestart.privateMemory',

        [Parameter(DontShow)]
        [Int64]$MemoryDefault = 1GB
    )

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath
        
        if($PreConfigMemory -eq 0) {
        
            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $MemoryDefault
        }

        $PostConfigMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

        [PSCustomObject] @{

            Vulnerability = "V-76871" 
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigMemory = [String]$PreConfigMemory.Value
            PostConfigMemory = [String]$PostConfigMemory.Value
            Compliant = if($PostConfigMemory.Value -gt 0) {
    
                "Yes"
            }

            else {
       
                "No: Value must be set higher than 0"
            }
        }
    }
}

function V-76873 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Event Log settings for vulnerability 76873.

.DESCRIPTION
    Configure and verify Application Pool Event Log settings for vulnerability 76873.
#>  
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'recycling.logEventOnRecycle'
    )

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

    #STIG required log fields
    $RequiredPoolFields = @(
            
        "Time",
        "Schedule"
    )

    #Current log fields
    $CurrentPoolFields = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Split(",")

    #Combine STIG fields and current fields (to ensure nothing is turned off, only turned on)
    [String[]]$PoolCollection = @(
            
        $RequiredPoolFields
        $CurrentPoolFields
    )

    [String]$PoolCollectionString = ($PoolCollection | Select -Unique)

    $PoolReplace = $PoolCollectionString.Replace(' ',",")

        $PreConfigPool = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath
        
        Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $PoolReplace

        $PostConfigPool = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

        [PSCustomObject] @{

            Vulnerability = "V-76873" 
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigPool = $PreConfigPool
            PostConfigPool = $PostConfigPool
            Compliant = if($PostConfigPool -like "*Time*" -and $PostConfigPool -like "*Schedule*") {
    
                "Yes"
            }

            else {
       
                "No: Time and Scheduled logging must be turned on"
            }
        }
    }
}

function V-76875 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Queue Length settings for vulnerability 76875.

.DESCRIPTION
    Configure and verify Application Pool Queue Length settings for vulnerability 76875.
#>  
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'queueLength',

        [Parameter(DontShow)]
        [Int]$QLength = 1000
    )

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigQLength = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value
        
        if($PreConfigQLength.Value -gt 1000) {
        
            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $QLength
        }

        $PostConfigQLength = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        [PSCustomObject] @{

            Vulnerability = "V-76875" 
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigQLength = $PreConfigQLength
            PostConfigQLength = $PostConfigQLength
            Compliant = if($PostConfigQLength -le 1000) {
    
                "Yes"
            }

            else {
       
                "No: Value must be 1000 or less"
            }
        }
    }
}

function V-76877 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Ping settings for vulnerability 76877.

.DESCRIPTION
    Configure and verify Application Pool Ping settings for vulnerability 76877.
#>  
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'processModel.pingingEnabled'
    )

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigPing = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value
        
        Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $true

        $PostConfigPing = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        [PSCustomObject] @{

            Vulnerability = "V-76877" 
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigPing = $PreConfigPing
            PostConfigPing = $PostConfigPing
            Compliant = if($PostConfigPing -eq $true) {
    
                "Yes"
            }

            else {
       
                "No"
            }
        }
    }
}

function V-76879 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Rapid-Fail Protection settings for vulnerability 76879.

.DESCRIPTION
    Configure and verify Application Pool Rapid-Fail Protection settings for vulnerability 76879.
#>  
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'failure.rapidFailProtection'
    )

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigRapidFailEnabled = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value
        
        Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $true

        $PostConfigRapidFailEnabled = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        [PSCustomObject] @{

            Vulnerability = "V-76877" 
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigRapidFailEnabled = $PreConfigRapidFailEnabled
            PostConfigRapidFailEnabled = $PostConfigRapidFailEnabled
            Compliant = if($PostConfigRapidFailEnabled -eq $true) {
    
                "Yes"
            }

            else {
       
                "No"
            }
        }
    }
}

function V-76881 {
<#
.SYNOPSIS 
    Configure and verify Application Pool Rapid-Fail Inetrval settings for vulnerability 76881.

.DESCRIPTION
    Configure and verify Application Pool Rapid-Fail Interval settings for vulnerability 76881.
#>  
    param(

        [Parameter(DontShow)]
        [String]$FilterPath = 'failure.rapidFailProtectionInterval',

        [Parameter(DontShow)]
        $ProtectionInterval = "00:05:00"

    )

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        if([Int]([TimeSpan]$PreConfigProtectionInterval).TotalMinutes -gt 5) {

            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $ProtectionInterval
        }

        $PostConfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        [PSCustomObject] @{

            Vulnerability = "V-76881" 
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigProtectionInterval = [Int]([TimeSpan]$PreConfigProtectionInterval).TotalMinutes
            PostConfigProtectionInterval = [Int]([TimeSpan]$PostConfigProtectionInterval).TotalMinutes
            Compliant = if([Int]([TimeSpan]$PostConfigProtectionInterval).TotalMinutes -le 5) {

                "Yes"
            }

            else {
       
                "No: Value must be 5 or less"
            }
        }
    }
}

function V-76883 {
<#
.SYNOPSIS 
    Configure and verify Alternate Hostname settings for vulnerability 76883.

.DESCRIPTION
    Configure and verify Alternate Hostname settings for vulnerability 76883.
#>  
    param(
        
        [Parameter(DontShow)]
        [String]$PSpath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [String]$FilterPath = 'system.webserver/serverRuntime'
    )

    foreach($WebName in $WebNames) {

        $PreConfigHostname = (Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name alternateHostname).Value
        
        if([String]::IsNullOrWhiteSpace($PreConfigHostname)) {

            [String]$AlternateHostName = "$(($WebName).Replace(' ','')).$((Get-CimInstance -ClassName Win32_ComputerSystem).Domain)"
        
            Set-WebConfigurationProperty -PSPath $PSPath/$($WebName) -Filter $FilterPath -Name alternateHostname -Value $AlternateHostName
        }

        $PostConfigHostname = (Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name alternateHostname).Value

        [PSCustomObject] @{

            Vulnerability = "V-76883" 
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigHostname = $PreConfigHostname
            PostConfigHostname = $PostConfigHostname
            Compliant = if(!([String]::IsNullOrWhiteSpace($PostConfigHostname))) {
    
                "Yes"
            }

            else {
       
                "No"
            }
        }
    }
}

#Call functions, configure settings, and generate reports
V-76679-76779-76781 | Export-Csv -Path "$ServerPath\V-76679-76779-76781.csv" -NoTypeInformation -Force
V-76681-76783 | Export-Csv -Path "$ServerPath\V-76681-76783.csv" -NoTypeInformation -Force
V-76683-76785 | Export-Csv -Path "$ServerPath\V-76683-76785.csv" -NoTypeInformation -Force
V-76685-76787 | Export-Csv -Path "$ServerPath\V-76685-76787.csv" -NoTypeInformation -Force
V-76687-76689-76789-76791 | Export-Csv -Path "$ServerPath\V-76687-76689-76789-76791.csv" -NoTypeInformation -Force
V-76695-76697-76795 | Export-Csv -Path "$ServerPath\V-76695-76697-7679-76795.csv" -NoTypeInformation -Force
V-76701 | Export-Csv -Path "$ServerPath\V-76701.csv" -NoTypeInformation -Force
V-76703 | Export-Csv -Path "$ServerPath\V-76703.csv" -NoTypeInformation -Force
V-76707-76719 | Export-Csv -Path "$ServerPath\V-76707-76719.csv" -NoTypeInformation -Force
V-76709 | Export-Csv -Path "$ServerPath\V-76709.csv" -NoTypeInformation -Force
V-76711-76797 | Export-Csv -Path "$ServerPath\V-76711-76797.csv" -NoTypeInformation -Force
V-76713-76803 | Export-Csv -Path "$ServerPath\V-76713-76803.csv" -NoTypeInformation -Force
V-76715 | Export-Csv -Path "$ServerPath\V-76715.csv" -NoTypeInformation -Force
V-76717 | Export-Csv -Path "$ServerPath\V-76717.csv" -NoTypeInformation -Force
V-76725-76727-76777 | Export-Csv -Path "$ServerPath\V-76725-76727-76777.csv" -NoTypeInformation -Force
V-76731 | Export-Csv -Path "$ServerPath\V-76731.csv" -NoTypeInformation -Force
V-76733-76829 | Export-Csv -Path "$ServerPath\V-76733-76829.csv" -NoTypeInformation -Force
V-76735 | Export-Csv -Path "$ServerPath\V-76735.csv" -NoTypeInformation -Force
V-76737-76835 | Export-Csv -Path "$ServerPath\V-76737-76835.csv" -NoTypeInformation -Force
V-76753 | Export-Csv -Path "$ServerPath\V-76753.csv" -NoTypeInformation -Force
V-76755 | Export-Csv -Path "$ServerPath\V-76755.csv" -NoTypeInformation -Force
V-76757-76855 | Export-Csv -Path "$ServerPath\V-76757-76855.csv" -NoTypeInformation -Force
V-76759 | Export-Csv -Path "$ServerPath\V-76759.csv" -NoTypeInformation -Force
V-76767 | Export-Csv -Path "$ServerPath\V-76767.csv" -NoTypeInformation -Force
V-76769 | Export-Csv -Path "$ServerPath\V-76769.csv" -NoTypeInformation -Force
V-76771 | Export-Csv -Path "$ServerPath\V-76771.csv" -NoTypeInformation -Force
V-76773 | Export-Csv -Path "$ServerPath\V-76773.csv" -NoTypeInformation -Force
V-76775-76813 | Export-Csv -Path "$ServerPath\V-76775-76813.csv" -NoTypeInformation -Force
V-76805 | Export-Csv -Path "$ServerPath\V-76805.csv" -NoTypeInformation -Force
V-76809-76851-76861 | Export-Csv -Path "$ServerPath\V-76809-76851-76861.csv" -NoTypeInformation -Force
V-76811 | Export-Csv -Path "$ServerPath\V-76811.csv" -NoTypeInformation -Force
V-76817 | Export-Csv -Path "$ServerPath\V-76817.csv" -NoTypeInformation -Force
V-76819 | Export-Csv -Path "$ServerPath\V-76819.csv" -NoTypeInformation -Force
V-76821 | Export-Csv -Path "$ServerPath\V-76821.csv" -NoTypeInformation -Force
V-76823 | Export-Csv -Path "$ServerPath\V-76823.csv" -NoTypeInformation -Force
V-76825 | Export-Csv -Path "$ServerPath\V-76825.csv" -NoTypeInformation -Force
V-76827 | Export-Csv -Path "$ServerPath\V-76827.csv" -NoTypeInformation -Force
V-76831 | Export-Csv -Path "$ServerPath\V-76831.csv" -NoTypeInformation -Force
V-76837 | Export-Csv -Path "$ServerPath\V-76837.csv" -NoTypeInformation -Force
V-76839 | Export-Csv -Path "$ServerPath\V-76839.csv" -NoTypeInformation -Force
V-76841 | Export-Csv -Path "$ServerPath\V-76841.csv" -NoTypeInformation -Force
V-76859 | Export-Csv -Path "$ServerPath\V-76859.csv" -NoTypeInformation -Force
V-76867 | Export-Csv -Path "$ServerPath\V-76867.csv" -NoTypeInformation -Force
V-76869 | Export-Csv -Path "$ServerPath\V-76869.csv" -NoTypeInformation -Force
V-76871 | Export-Csv -Path "$ServerPath\V-76871.csv" -NoTypeInformation -Force
V-76873 | Export-Csv -Path "$ServerPath\V-76873.csv" -NoTypeInformation -Force
V-76875 | Export-Csv -Path "$ServerPath\V-76875.csv" -NoTypeInformation -Force
V-76877 | Export-Csv -Path "$ServerPath\V-76877.csv" -NoTypeInformation -Force
V-76879 | Export-Csv -Path "$ServerPath\V-76879.csv" -NoTypeInformation -Force
V-76881 | Export-Csv -Path "$ServerPath\V-76881.csv" -NoTypeInformation -Force
V-76883 | Export-Csv -Path "$ServerPath\V-76883.csv" -NoTypeInformation -Force

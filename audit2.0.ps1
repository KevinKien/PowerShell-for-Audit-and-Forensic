<#
Audit Tools v2.0
#>

$CompName = (gi env:\Computername).Value
$UserDirectory = (gi env:\userprofile).value
$User = (gi env:\USERNAME).value
$Date = (Get-Date).ToString('MM.dd.yyyy')
$head = '<style> BODY{font-family:caibri; background-color:Aliceblue;} TABLE{border-width: 1px;border-style: solid;border-color: black;bordercollapse:collapse;} TH{font-size:1.1em; border-width: 1px;padding: 2px;borderstyle:solid;border-color: black;background-color:PowderBlue} TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;backgroundcolor:white}</style>'
$OutFile = "$UserDirectory\desktop\Audit2.0.html"

function Get-NetworkStatistics 
{ 
    $properties = 'Protocol','LocalAddress','LocalPort' 
    $properties += 'RemoteAddress','RemotePort','State','ProcessName','PID'

    netstat -ano | Select-String -Pattern ‘\s+(TCP)’ | ForEach-Object {

        $item = $_.line.split(” “,[System.StringSplitOptions]::RemoveEmptyEntries)

        if($item[1] -notmatch '^\[::') 
        {            
            if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
            { 
               $localAddress = $la.IPAddressToString 
               $localPort = $item[1].split('\]:')[-1] 
            } 
            else 
            { 
                $localAddress = $item[1].split(':')[0] 
                $localPort = $item[1].split(':')[-1] 
            } 

            if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
            { 
               $remoteAddress = $ra.IPAddressToString 
               $remotePort = $item[2].split('\]:')[-1] 
            } 
            else 
            { 
               $remoteAddress = $item[2].split(':')[0] 
               $remotePort = $item[2].split(':')[-1] 
            } 

            New-Object PSObject -Property @{ 
                PID = $item[-1] 
                ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name 
                Protocol = $item[0] 
                LocalAddress = $localAddress 
                LocalPort = $localPort 
                RemoteAddress =$remoteAddress 
                RemotePort = $remotePort 
                State = if($item[0] -eq 'tcp') {$item[3]} else {$null} 
            } | Select-Object -Property $properties 
        } 
    } 
}

function getGpo {
    Import-Module GroupPolicy
    
    $now = Get-date
$date = get-date -uformat "%Y_%m_%d_%I%M%p"


[array]$Report = @()

$GPOs = Get-GPO -all | Sort-Object Displayname

foreach ($GPO in $GPOs) 
{
    Write-Host "Processing GPO $($GPO.DisplayName)"
    $XMLReport = Get-GPOReport -GUID $($GPO.id) -ReportType xml
    $XML = [xml]$XMLReport
    
    $Types = @("User","Computer")
    
    Foreach ($Type in $Types)
    {
    #Write-Host "Processing $Type GPO $($GPO.DisplayName)"
        $ExtArray = $xml.gpo.$Type.ExtensionData | foreach-Object -process {$_.name}
        
        if ($Type -eq "User"){$UserExtEnabled = $xml.gpo.$type.Enabled}
        if ($Type -eq "Computer"){$ComputerExtEnabled = $xml.gpo.$type.Enabled}
                        
        $ExtCount = $ExtArray.count
        #write-host "Extension count is $ExtCount"
                
        if (($ExtCount -eq $Null) -or ($ExtCount -eq 0))
        {
            #write-host "$Type is False"
            if ($Type -eq "User"){$UserExtEmpty = "No Settings"}
            if ($Type -eq "Computer"){$ComputerExtEmpty = "No Settings"}
        }
        
        Else
        {   
            #write-host "$Type is True"
            if ($Type -eq "User"){$UserExtEmpty = "Has Settings"}
            if ($Type -eq "Computer"){$ComputerExtEmpty = "Has Settings"}
        }
    }
    #write-host "Building Report"
    #write-host "Computer EXT $ComputerExtEnabled"
    #write-host "User Ext $UserExtEnabled"
    $Report += New-Object PSObject -Property @{
            'GPO Name' = $xml.gpo.name
            'User GPO Side Enabled' = $global:UserExtEnabled 
            'Computer GPO Side Enabled' = $global:ComputerExtEnabled 
            'Has Computer Settings' = $ComputerExtEmpty
            'Has User Settings' = $UserExtEmpty
            'GPO Status' = $GPO.GpoStatus
            'Last Modified' = $GPO.ModificationTime
            'Created on' = $GPO.CreationTime                    
    }
    Clear-variable UserExtEmpty
        Clear-variable ComputerExtEmpty
        Clear-variable UserExtEnabled
        Clear-variable ComputerExtEnabled
    Clear-Variable ExtArray
        Clear-Variable ExtCount
}

return $Report | select-object 'GPO Name','User GPO Side Enabled','Has User Settings','Computer GPO Side Enabled','Has Computer Settings','GPO Status','Last Modified','Created on' 

}


function get-update {
    $session = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$ComputerName))
    $us = $session.CreateUpdateSearcher()
    $qtd = $us.GetTotalHistoryCount()
    $hot = $us.QueryHistory(0, $qtd)

    foreach ($Upd in $hot) {
        $OutPut = New-Object -Type PSObject -Prop @{
            
            'UpdateDate'=$Upd.date
            'KB'=[regex]::match($Upd.Title,'KB(\d+)')
            'UpdateTitle'=$Upd.title
            'UpdateDescription'=$Upd.Description
            'SupportUrl'=$Upd.SupportUrl
            'UpdateId'=$Upd.UpdateIdentity.UpdateId
            'RevisionNumber'=$Upd.UpdateIdentity.RevisionNumber
            
        }
        return $OutPut
    }
}

function Get-Info {

    try {
        Import-Module GroupPolicy
        Import-Module ActiveDirectory
    } catch {

    }

	#Title
	ConvertTo-Html -Head $head -Title "Audit Tools" -Body "<h1>Audit Tools v2</h1>" > $OutFile 

	#Get OS 
	$os = (Get-WmiObject Win32_OperatingSystem).Name
	$osname = $os.split("|")
    $osname = $osname[0]

	#Get ver
	$ver = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

	#Get Computername
	$cname = (Get-WmiObject Win32_OperatingSystem).CSName
	"OS: $osname $ver <br> ComputerName: $cname" >> $OutFile

	#Get port listening
	Get-NetworkStatistics | where {$_.state -eq "LISTENING"} | ConvertTo-html -Head $head -Body "<H2>Port</H2>" >> $OutFile

	#Get infor process
	gwmi -ea 0 win32_process | select Processname, @{name="CreateDate"; expression={$_.converttodatetime($_.creationdate)}}, ProcessID, ParentProcessID, CommandLine, SessionID | sort parentprocessid -desc | ConvertTo-html -Head $head -Body "<H2> Running Processes</H2>" >> $OutFile

	#Get service running
	gwmi -ea 0 win32_service | select Name, ProcessID, State, DisplayName, PathName | sort state -desc | ConvertTo-html -Head $head -Body "<H2>Running Sevice</H2>" >> $OutFile

	#Get update
	#Get-HotFix  -ea 0 | select HotFixid, Description, Installedby, Installedon | ConvertTo-html -Head $head -Body "<H2>Update</H2>" >> $OutFile
    get-update | ConvertTo-html -Head $head -Body "<H2>Update</H2>" >> $OutFile

	#Get user
	gwmi -ea 0 win32_useraccount | select Caption, Domain, Name, SID, PasswordExpires | ConvertTo-html -Head $head -Body "<H2>User</H2>" >> $OutFile

    #Get GPO
    try {
        getGpo | ConvertTo-html -Head $head -Body "<H2>GPO</H2>" >> $OutFile
    } catch {
        write-host "GPO not found"
    }

    #File sharing
    gwmi -ea 0 Win32_Share | select name,path,description | ConvertTo-html -Body "<H2> Open Shares </H2>" >> $OutFile

    #File analysis
    gwmi -ea 0 Win32_ShortcutFile | select FileName,caption,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},@{NAME='LastAccessed';EXPRESSION={$_.ConvertToDateTime($_.LastAccessed)}},@{NAME='LastModified';EXPRESSION={$_.ConvertToDateTime($_.LastModified)}},Target | Where-Object {$_.lastModified -gt ((Get-Date).addDays(-5)) }| sort LastModified -Descending | ConvertTo-html -Body "<H2> Link File Analysis -Last 5 days </H2>" >> $OutFile

    #Event log - A user account was created
    Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4720} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - A user account was created </H2>" >> $OutFile

    #Event log Account logon
    #Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4624} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - Account logon </H2>" >> $OutFile

    write-host "Done!! file audit2.0.html"

    #GPO report
    #Get-GPOReport -All -ReportType HTML $UserDirectory\desktop\gporeport.html
    GPResult.exe /H "$UserDirectory\desktop\gporeport.html"

    write-host "Done!! file gporeport.html"

    #Firewall config
    netsh firewall show config > "$UserDirectory\desktop\FirewallConfig.txt"

    write-host "Done!! file FirewallConfig.txt"

    #audit policy
    auditpol.exe /get /category:* > "$UserDirectory\desktop\auditpol.txt"

    write-host "Done!! file auditpol.txt"

}

#main
try {
    Get-Info
    write-host "Done!!!"
}
catch {
    write-host " "
}

Clear-Content Ping.txt

# scanForAvailableIps_v0.02.ps1
# Requires: Powershell 3.0+
 
#$cidrBlock='10.17.130.0/23'
$start='192.168.0.1'
$end='192.168.0.254'
$limit=100

function scanForAvailableIPs{
    param(        
        [string]$start,
        [string]$end,
        [string]$ip,
        [string]$mask,
        [string]$cidr,
        [string]$cidrBlock,
        [string]$limit, # Assuming CIDR /16        
        [string]$getUnavailabeIps=$false
        )
     
    function Get-IPrange{
        <# This Get-IPrange function has been obtained at Gallery Technet
        Snippet Author: BarryCWT
        .SYNOPSIS  
        Get the IP addresses in a range 
        .EXAMPLE 
        Get-IPrange -start 192.168.8.2 -end 192.168.8.20 
        .EXAMPLE 
        Get-IPrange -ip 192.168.8.2 -mask 255.255.255.0 
        .EXAMPLE 
        Get-IPrange -ip 192.168.8.3 -cidr 24 
        #>
   
        param ( 
        [string]$start, 
        [string]$end, 
        [string]$ip, 
        [string]$mask, 
        [int]$cidr
        ) 
   
        function IP-toINT64 () { 
            param ($ip) 
   
            $octets = $ip.split(".") 
            return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
        } 
   
        function INT64-toIP() { 
            param ([int64]$int) 
  
            return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
        } 
   
        if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
        if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
        if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
        if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
        if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
   
        if ($ip) { 
            $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
            $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
        } else { 
            $startaddr = IP-toINT64 -ip $start
            $endaddr = IP-toINT64 -ip $end
        } 
   
   
        for ($i = $startaddr; $i -le $endaddr; $i++) 
        { 
            INT64-toIP -int $i
        }
  
    }
  
    # Regex values
    $regexIP = [regex] "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    $regexCidr=[regex] "\/(.*)"
    $regexFourthOctetValue=[regex] ".+\..+\..+\.(.+)"
     
    # Process inputs
    if ($start -and $end){
        $allIPs=Get-IPrange -start $start -end $end
    }elseif($ip -and $mask){
        $allIPs=Get-IPrange -ip $ip -mask $mask
    }elseif($ip -and $cidr){
        $allIPs=Get-IPrange -ip $ip -cidr $cidr
    }elseif($cidrBlock){
        $ip=$regexIP.Matches($cidrBlock).Value
        $cidr=$regexCidr.Matches($cidrBlock).Groups[1].Value
        $allIPs=Get-IPrange -ip $ip -cidr $cidr       
    }else{ # This will be the catchall when function is called without any arguments
        $cidrBlock=$(
                $interfaceIndex=(Get-WmiObject -Class Win32_IP4RouteTable | where { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} |  Sort-Object metric1).interfaceindex;
                $interfaceObject=(Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily ipv4|select IPAddress,PrefixLength)[0];
                "$($interfaceObject.IPAddress)/$($interfaceObject.PrefixLength)")        
        $ip=$regexIP.Matches($cidrBlock).Value
        $cidr=$regexCidr.Matches($cidrBlock).Groups[1].Value
        $allIPs=Get-IPrange -ip $ip -cidr $cidr
        }
  
    # Remove fourth octet values matching 0,1, and 255
    #if($regexFourthOctetValue.Matches($allIPs[0]).Groups[1].Value -eq 0){$first, $rest= $allIPs; $allIPs=$rest;}
    #if($regexFourthOctetValue.Matches($allIPs[0]).Groups[1].Value -eq 1){$first, $rest= $allIPs; $allIPs=$rest;}    
    if($regexFourthOctetValue.Matches($allIPs[$allIPs.length-1]).Groups[1].Value -eq 255){$allIPs = $allIPs | ? {$_ -ne $allIPs[$allIPs.count-1]}}
  
    # Display sweep scanning output
    #$allIPs | ForEach-Object {if(!(Get-WmiObject Win32_PingStatus -Filter "Address='$_' and Timeout=200 and ResolveAddressNames='true' and StatusCode=0" | select ProtocolAddress*)){$_}}
  
    # Collect unpingable IPs
    "Collecting available IPs. Please wait awhile..."
    if(!$limit){$limit=$allIPs.count}
    $i=0
    $simultaneousJobs=8
    $pingCommand={
        param($ipAddress)
        [bool]$pingable=!(!(Get-WmiObject Win32_PingStatus -Filter "Address='$ipAddress' and Timeout=200 and ResolveAddressNames='true' and StatusCode=0"))
        return @{$ipAddress=$pingable}
        }
    $results=@{}
    foreach ($ipAddress in $allIps){
        if($i++ -lt $simultaneousJobs){                
            Start-Job $pingCommand -ArgumentList $ipAddress|Out-Null
        }else{
            do{
                $result=Get-Job | Receive-Job #-Wait
                if($result){          
                    $result|%{$_.GetEnumerator()|%{write-host "$($_.Key) pingable`t: $($_.Value)";$results[$_.Key]=$_.Value}}                    
                    get-job -State Completed|remove-job
                    }                
                $i=(get-job -state 'Running').count
                }until($i -lt $simultaneousJobs)              
            }
        $desiredResults=if(!$getUnavailabeIps){$results.GetEnumerator()|?{$_.value}}else{$results.GetEnumerator()|?{!($_.value)}}
        if($desiredResults.count -ge $limit){            
            #write-host "Results count $($desiredResults.count) reached."  
            write-host "`r`n------------------------------------------`r`nScanner stopped at $($desiredResults.count) as limit of $limit results have been reached." -ForegroundColor Yellow
            return $desiredResults.GetEnumerator()|%{$_.Name}|Sort|select -First $limit
            }  
        }
    write-host "No results."
    return $false
}
  
scanForAvailableIPs -start $start -end $end -limit $limit >> Ping.txt
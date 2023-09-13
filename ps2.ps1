<#
.SYNOPSIS
A port scanner written purely in PowerShell
.Description
A port scanner written purely in PowerShell

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by James Conlan, James.Conlan@nccgroup.com

<GitHub Link>

You should have received a copy of the GNU General Public License along with 
PS2. If not, see https://www.gnu.org/licenses.
.PARAMETER banners
(-b) Attempt to grab banners from open ports
.PARAMETER delay
(-d) Delay to use between each connection in milliseconds
.PARAMETER inFiles
(-f) File(s) containing targets to scan (1 per line)
.PARAMETER help
(-h) Displays help information
.PARAMETER ips
(-i) IP address(es) of target(s) to scan (supports individual IPv4 addresses, IPv4 address ranges, IPv4 CIDR notation, and individual IPv6 addresses)
.PARAMETER serviceMap
(-m) Service map to use (overrides default of <PS2_dir>/servicemap.csv)
.PARAMETER hostnames
(-n) Hostname(s) of target(s) to scan
.PARAMETER noColour
(-nC) Do not use colour in terminal output
.PARAMETER noPing
(-nP) Assume all hosts are up and do not ping them prior to scanning
.PARAMETER overwrite
(-o) Force output files to be overwritten if they exist and do not prompt for confirmation
.PARAMETER outAll
(-oA) Save output in txt and JSON formats to files with a specified name (supersedes -oJ and -oT options)
.PARAMETER outJson
(-oJ) Save output in JSON format to a specified file
.PARAMETER outTxt
(-oT) Save output in txt format to a specified file
.PARAMETER ports
(-p) Port(s) to scan (overrides default of top 20 commonly used ports)
.PARAMETER randomise
(-r) Randomise the order in which hosts and ports are scanned
.PARAMETER timeout
(-t) Timeout to use for connections in milliseconds (overrides default of 1000ms)
.PARAMETER traceroute
Trace hop path to each host
.PARAMETER udp
(-u) Perform a UDP scan instead of TCP connect scan
.PARAMETER v
(-Verbose, -vb) Show verbose output
#>


<###############################################################################
# CLI Parameters                                                               #
###############################################################################>

[cmdletbinding()]
param([Parameter(Mandatory=$false)][alias("b")][switch] $banners,
      [Parameter(Mandatory=$false)][alias("d")][int] $delay,
      [Parameter(Mandatory=$false)][alias("f")][System.IO.FileInfo[]] $inFiles,
      [Parameter(Mandatory=$false)][alias("h")][switch] $help,
      [Parameter(Mandatory=$false)][alias("n")][string[]] $hostnames,
      [Parameter(Mandatory=$false)][alias("i")][string[]] $ips,
      [Parameter(Mandatory=$false)][alias("m")][System.IO.FileInfo] $serviceMap,
      [Parameter(Mandatory=$false)][alias("nC")][switch] $noColour,
      [Parameter(Mandatory=$false)][alias("nP")][switch] $noPing,
      [Parameter(Mandatory=$false)][alias("o")][switch] $overwrite,
      [Parameter(Mandatory=$false)][alias("oA")][System.IO.FileInfo] $outAll,
      [Parameter(Mandatory=$false)][alias("oJ")][System.IO.FileInfo] $outJson,
      [Parameter(Mandatory=$false)][alias("oT")][System.IO.FileInfo] $outTxt,
      [Parameter(Mandatory=$false)][alias("p")][int[]][ValidateRange(0, 65535)] $ports,
      [Parameter(Mandatory=$false)][alias("r")][switch] $randomise,
      [Parameter(Mandatory=$false)][alias("t")][int][ValidateRange(0, [int]::MaxValue)] $timeout,
      [Parameter(Mandatory=$false)][switch] $traceroute,
      [Parameter(Mandatory=$false)][alias("u")][switch] $udp,
      [Parameter(Mandatory=$false)][switch] $v
     )


<###############################################################################
# Config                                                                 #
###############################################################################>

$defDelay = 0
$defTimeout = 1000
$defSvcMap = "$(Split-Path $MyInvocation.MyCommand.Path)\servicemap.csv"
$defTcpPorts = @(21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080)
$defUdpPorts = @(53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 49152)
$udpPayloads = @{
    7 =  @([byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" }));
    11 = @([byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" }));
    13 = @([byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" }));
    19 = @([byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" }));
    37 = @([byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" }));
    53 = @([byte[]] $('00','00','10','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" }),
           [byte[]] $('00','06','01','00','00','01','00','00','00','00','00','00','07','76','65','72','73','69','6f','6e','04','62','69','6e','64','00','00','10','00','03'| foreach-object { invoke-expression "0x$_" }));
    69 = @([byte[]] $('00','01','2f','65','74','63','2f','70','61','73','73','77','64','00','6e','65','74','61','73','63','69','69','00' | foreach-object { invoke-expression "0x$_" }));
    111 = @([byte[]] $('03','9b','65','42','00','00','00','00','00','00','00','02','00','0f','42','43','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" }),
            [byte[]] $('72','FE','1D','13','00','00','00','00','00','00','00','02','00','01','86','A0','00','01','97','7C','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" }));
    123 = @([byte[]] $('cb','00','04','fa','00','01','00','00','00','01','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','bf','be','70','99','cd','b3','40','00' | foreach-object { invoke-expression "0x$_" }));
    137 = @([byte[]] $('80','f0','00','10','00','01','00','00','00','00','00','00','20','43','4b','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','00','00','21','00','01' | foreach-object { invoke-expression "0x$_" }));
    161 = @([byte[]] $('30','82','00','2f','02','01','00','04','06','70','75','62','6c','69','63','a0','82','00','20','02','04','4c','33','a7','56','02','01','00','02','01','00','30','82','00','10','30','82','00','0c','06','08','2b','06','01','02','01','01','05','00','05','00' | foreach-object { invoke-expression "0x$_" }),
            [byte[]] $('30','3a','02','01','03','30','0f','02','02','4a','69','02','03','00','ff','e3','04','01','04','02','01','03','04','10','30','0e','04','00','02','01','00','02','01','00','04','00','04','00','04','00','30','12','04','00','04','00','a0','0c','02','02','37','f0','02','01','00','02','01','00','30','00'| foreach-object { invoke-expression "0x$_" }));
    177 = @([byte[]] $('00','01','00','02','00','01','00','00' | foreach-object { invoke-expression "0x$_" }));
    500 = @([byte[]] $('5b','5e','64','c0','3e','99','b5','11','00','00','00','00','00','00','00','00','01','10','02','00','00','00','00','00','00','00','01','50','00','00','01','34','00','00','00','01','00','00','00','01','00','00','01','28','01','01','00','08','03','00','00','24','01','01' | foreach-object { invoke-expression "0x$_" }));
    523 = @([byte[]] $('44','42','32','47','45','54','41','44','44','52','00','53','51','4c','30','38','30','32','30' | foreach-object { invoke-expression "0x$_" }));
    1434 = @([byte[]] $('02' | foreach-object { invoke-expression "0x$_" }),
             [byte[]] $('0A' | foreach-object { invoke-expression "0x$_" })); 
    1604 = @([byte[]] $('1e','00','01','30','02','fd','a8','e3','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" }));
    2123 = @([byte[]] $('32','01','00','04','00','00','00','00','50','00','00','00' | foreach-object { invoke-expression "0x$_" }));
    5405 = @([byte[]] $('01','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','80','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" }));
    6502 = @([byte[]] $('d6','81','81','52','00','00','00','f3','87','4e','01','02','32','00','a8','c0','00','00','01','13','c1','d9','04','dd','03','7d','00','00','0d','00','54','48','43','54','48','43','54','48','43','54','48','43','54','48','43','20','20','20','20','20','20','20','20','20','20','20','20','20','20','20','20','20','02','32','00','a8','c0','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" }))
}

<###############################################################################
# Functions                                                                    #
###############################################################################>

function writeOut {
    <#
    .SYNOPSIS
    Writes output to screen and output file if specified
    .PARAMETER text
    Text to write (required)
    .PARAMETER file
    Output file to write to
    .PARAMETER foreground
    Foreground colour to use in terminal output
    .PARAMETER background
    Background colour to use in terminal output
    .PARAMETER NoNewLine
    Do not add a new line after the supplied text
    #>
    param([Parameter(Mandatory=$true)] $text,
          [Parameter(Mandatory=$false)][string] $file,
          [Parameter(Mandatory=$false)][System.ConsoleColor] $foreground,
          [Parameter(Mandatory=$false)][System.ConsoleColor] $background,
          [Parameter(Mandatory=$false)][switch] $NoNewLine
         )
    if ($file) {
        Out-File -InputObject "$text" -FilePath $file -Append -NoNewline:$NoNewLine
    }
    if ($noColour -Or -Not $foreground) {
        $foreground = [System.Console]::ForegroundColor
    }
    if ($noColour -Or -Not $background) {
        $background = [System.Console]::BackgroundColor
    }
    Write-Host "$text" -ForegroundColor $foreground -BackgroundColor $background -NoNewline:$NoNewLine
}

function writeJson {
    <#
    .SYNOPSIS
    Writes output to JSON file
    .PARAMETER json
    JSON to write (required)
    .PARAMETER level
    Indentation level (required)
    .PARAMETER file
    JSON file to write to
    #>
    param([Parameter(Mandatory=$true)][string] $json,
          [Parameter(Mandatory=$true)][int] $level,
          [Parameter(Mandatory=$false)][string] $file
         )
    if ($file) {
        $indent = "    " * $level
        $json = $json.TrimEnd()
        $json = $json.replace("\", "\\")
        $json = $json.replace([Environment]::NewLine, "\n")
        Out-File -InputObject "$indent$json" -FilePath $file -Append
    }
}
     
function yN {
    <#
    .SYNOPSIS
    Prompts for a yes/no answer to a question
    .PARAMETER prompt
    Prompt text to display to user (required)
    .OUTPUTS
    Returns $true if yes and $false if no
    #> 
    param([Parameter(Mandatory=$true)][string] $prompt)
    while ($true) {
        $conf = Read-Host "$prompt (y/n)"
        switch ($conf.ToLower()) {
            "n" {return $false}
            "y" {return $true}
        }
    }
}

function checkOutFile {
    <#
    .SYNOPSIS
    Checks if an output file exists and overwrites it if requested
    .PARAMETER file
    File to check (required)
    #>
    param([Parameter(Mandatory=$true)][System.IO.FileInfo] $file)
    if ($file | Test-Path) {
        if (-Not $overwrite -and -Not (yN -prompt "'$file' exists, overwrite it?")) {
            Exit
        }
        Tee-Object -FilePath $file
    }
}

function checkTargets {
    <#
    .SYNOPSIS
    Checks given targets are valid
    .PARAMETER targets
    List of targets to check (required)
    .OUTPUTS
    List of valid targets
    #>
    param([Parameter(Mandatory=$true)][string[]] $targets)
    $valid = @()
    $targets = $targets | Sort-Object -unique
    foreach ($target in $targets) {
        $ipObj = $target -as [ipaddress]
        if ($null -ne $ipObj) {
            $valid += $ipObj
            continue
        }
        $range, $cidr = $target.split("/")
        $octs = $range.split(".")
        if ($octs.Length -eq 4) {
            if (-Not $cidr) {
                try {
                    $rangeMin, $rangeMax = $octs[3].split("-") -as [int[]]
                    $range = $rangeMin..$rangeMax
                    foreach ($val in $range) {
                        $valid += [ipaddress]"$($octs[0]).$($octs[1]).$($octs[2]).$val"
                    }
                    continue
                } catch {
                    Throw "Target '$target' is not a valid IP address range"
                }
            } else {
                try {
                    $numHosts = [Math]::Pow(2, (32 - [int]$cidr)) - 2
                    for (($i = 0); $i -lt $numHosts; $i++) {
                        foreach ($octIdx in ($octs.Length - 1)..0) {
                            if ([int]$octs[$octIdx] -lt 255) {
                                $octs[$octIdx] = [int]$octs[$octIdx] + 1
                                break
                            } else {
                                $octs[$octIdx] = 0
                            }
                        }
                        $valid += [ipaddress]($octs -join ".")
                    }
                    continue
                } catch {
                    Throw "Target '$target' is not valid CIDR notation"
                }
            }
        }
        Throw "Target '$target' is not a valid IPv4 address range, IPv6 address, or file"
    }
    $valid = $valid | Sort-Object -unique -Property { try {[Version]$_.IPAddressToString} catch {$_.IPAddressToString} }
    return $valid
}

function dnsLookup {
    <#
    .SYNOPSIS
    Gets IP addresses for a given hostname
    .PARAMETER targets
    List of hostnames to look up (required)
    .OUTPUTS
    List of IP addresses
    #>
    param([Parameter(Mandatory=$true)][string[]] $targets)
    $resolved = @()
    foreach ($target in $targets) {
        if ($verbose) {
            writeOut -text "Resolving '$target'..." -NoNewLine
        }
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($target)
            foreach ($addr in $addrs) {
                $resolved += $addr
            }
        } catch {
            Throw "Could not resolve hostname '$target'"
        }
        if ($verbose) {
            writeOut -text " $($addrs -join ', ')"
        }
    }
    return $resolved
}


<###############################################################################
# Setup                                                                        #
###############################################################################>

# Convert non-terminating errors to terminating
$ErrorActionPreference = "Stop"

# Define help behaviour
if ($help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    Exit
}

# Check targets have been specified
if (-Not $inFiles -and -Not $ips -and -Not $hostnames) {
    Throw "Please specify at least one of -i/-ips, -n/-hostnames, or -f/-inFiles"
}

# Define verbosity
if ($v -Or $PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
    $verbose = $true
}

# Initialise target list
$targets = @()

# Parse input files
if ($inFiles) {
    foreach ($file in $inFiles) {
        if (-Not ($file | Test-Path -PathType Leaf)) {
            Throw "'$file' is not a valid input file"
        }
        foreach ($line in Get-Content $file) {
            try {
                $targets += checkTargets -targets ($line.Trim())
            } catch {
                try {
                    $targets += dnsLookup -targets ($line.Trim())
                } catch {
                    Throw "'$line' is not a valid target"
                }
            }
        }
    }
}

# Check IPs
if ($ips) {
    $targets += checkTargets -targets $ips
}

# Check hostnames
if ($hostnames) {
    $targets += dnsLookup -targets $hostnames
}

# Process target list
$targets = $targets | Sort-Object -unique -Property { try {[Version]$_.IPAddressToString} catch {$_.IPAddressToString} }
if ($randomise) {
    $targets = $targets | Sort-Object {Get-Random}
}

# Get service map
if ($serviceMap) {
    if (-Not ($serviceMap | Test-Path)) {
       Throw "Service map file '$serviceMap' does not exist"
    }
    $csvPath = $serviceMap
} else {
   $csvPath = $defSvcMap
}
$svcMap = @()
if ($csvPath | Test-Path) {
   $csv = Import-Csv -Header 'Service', 'Port', 'Protocol' $csvPath
   foreach ($row in $csv) {
       $svcMap += (@{
           Service = $row.("Service")
           Port = [int]$row.("Port")
           Protocol = $row.("Protocol").ToLower()
       })
   }
}

# Set default delay if no delay specified
if (-Not $delay) {
    $delay = $defDelay
}

# Set default timeout if no timeout specified
if (-Not $timeout) {
    $timeout = $defTimeout
}

# Set default ports if no ports specified
if (-Not $ports) {
    if ($udp) {
        $ports = $defUdpPorts
    } else {
        $ports = $defTcpPorts
    }
}
$ports = $ports | Sort-Object -unique
if ($randomise) {
    $ports = $ports | Sort-Object {Get-Random}
}

# Set protocol
if ($udp) {
    $protocol = "udp"
} else {
    $protocol = "tcp"
}

# Prepare output files
if ($outAll) {
    $outTxt = $outAll
    $outJson = $outAll
}
$cmd = $MyInvocation.Line
if ($outTxt) {
    if ($outTxt.Name -notmatch '\.txt$') {
        $outTxt = "$($outTxt.Name).txt"
    }
    checkOutFile -file $outTxt
    Out-File -InputObject "Command: $cmd`n" -FilePath $outTxt -Append
}
if ($outJson) {
    if ($outJson.Name -notmatch '\.json$') {
        $outJson = "$($outJson.Name).json"
    }
    checkOutFile -file $outJson
    writeJson -json "{" -level 0 -file $outJson
    writeJson -json "`"command`": `"$cmd`"," -level 1 -file $outJson
}


<###############################################################################
# Scan                                                                         #
###############################################################################>

$startTime = Get-Date
writeJson -json "`"startTime`": `"$startTime`"," -level 1 -file $outJson
writeOut -text "PS2 scan commenced at: $startTime" -file $outTxt
$results = @{}
$encoder = new-object system.text.asciiencoding
writeJson -json "`"hosts`": [" -level 1 -file $outJson
$numTargets = $targets.Length
$count = 0
foreach ($ip in $targets) {
    if (-Not $verbose) {
        $progressParams = @{
            Activity = "Scanning $numTargets hosts"
            Status = "($count/$numTargets)"
            PercentComplete = [math]::Round(($count / $numTargets) * 100)
            CurrentOperation = "Scanning $ip"
        }
        Write-Progress @progressParams
    }
    $results["$ip"] = @{Ports = @()}
    writeJson -json "{" -level 2 -file $outJson
    writeJson -json "`"ip`": `"$($ip.IPAddressToString)`"," -level 3 -file $outJson
    # Ping host
    if (-Not $noPing) {
        if ($verbose) {
            writeOut -NoNewLine -text "Pinging $($ip.IPAddressToString)... "
        }
        if ([version]$PSVersionTable.PSVersion -lt [version]"6.0.0") {
            try {
                $ping = Test-Connection $ip.IPAddressToString -Quiet
            } catch {
                $ping = $false
            }
        } else {
            $timeoutSecs = [int][math]::ceiling($timeout/1000)
            try {
                $ping = Test-Connection -TargetName $ip.IPAddressToString -TimeoutSeconds $timeoutSecs -Quiet
            } catch {
                $ping = $false
            }
        }
        $results["$ip"]["Status"] = "Up"
        $results["$ip"]["StatusColour"] = "DarkGreen"
        if ($verbose) {
            writeOut -text "Host is " -NoNewLine
        }
        if ($ping) {
            if ($verbose) {
                writeOut -text "up" -foreground "DarkGreen"
            }
            writeJson -json "`"status`": `"Up`"," -level 3 -file $outJson
        } else {
            $results["$ip"]["Status"] = "Down"
            $results["$ip"]["StatusColour"] = "DarkRed"
            if ($verbose) {
                writeOut -text "down" -foreground "DarkRed"
            }
            writeJson -json "`"status`": `"Down`"," -level 3 -file $outJson
            if ($traceroute) {
                writeJson -json "`"traceroute`": null," -level 3 -file $outJson
            }
            writeJson -json "`"ports`": null" -level 3 -file $outJson
            if ($ip -eq $targets[-1]) {
                writeJson -json "}" -level 2 -file $outJson
            } else {
                writeJson -json "}," -level 2 -file $outJson
            }
            continue
        }
    } else {
        if ($verbose) {
            writeOut -text "Assuming $($ip.IPAddressToString) host is up" -foreground "Yellow"
        }
        $results["$ip"]["Status"] = "Assumed Up"
        $results["$ip"]["StatusColour"] = "Yellow"
        writeJson -json "`"status`": `"Assumed Up`"," -level 3 -file $outJson
    }
    if ($traceroute) {
        if ($verbose) {
            writeOut -text "Performing traceroute for $ip... " -NoNewLine
        }
        $results["$ip"]["Traceroute"] = @()
        writeJson -json "`"traceroute`": {" -level 3 -file $outJson
        try {
            $Global:ProgressPreference = 'SilentlyContinue'
            $tr = Test-NetConnection -TraceRoute $ip -WarningAction:Stop 3>$null | Select-Object -ExpandProperty TraceRoute
            $Global:ProgressPreference = 'Continue'
            $trCount = 1
            foreach ($hop in $tr) {
                if ($trCount -eq $tr.Length) {
                    writeJson -json "`"${trCount}`": `"$hop`"" -level 4 -file $outJson
                } else {
                    writeJson -json "`"${trCount}`": `"$hop`"," -level 4 -file $outJson
                }
                $results["$ip"]["Traceroute"] += @{"Hop" = $trCount; "Host" = $hop}
                $trCount += 1
            }
            if ($verbose) {
                writeOut -text "Done" -foreground "DarkGreen"
            }
        } catch {
            $results["$ip"]["Traceroute"] += @{"Hop" = 0; "Host" = "Traceroute failed"}
            writeJson -json "`"0`": `"Traceroute failed`"" -level 4 -file $outJson
            if ($verbose) {
                writeOut -text "Failed" -foreground "DarkRed"
            }
        }
        writeJson -json "}," -level 3 -file $outJson
    }
    writeJson -json "`"ports`": [" -level 3 -file $outJson
    foreach ($port in $ports) {
        Start-Sleep -Milliseconds $delay
        if ($verbose) {
            writeOut -NoNewLine -text "Scanning $($ip.IPAddressToString) port $port/$protocol... "
        }
        $result = @{}
        $result["Port"] += $port
        $result["Protocol"] += $protocol
        if ($udp) {
            # UDP scan
            $payloads = @()
            if ($udpPayloads.ContainsKey($port)) {
                $payloads = $udpPayloads[$port]
            }
            $payloads += $encoder.GetBytes("$(Get-Date)")
            foreach($bytes in $payloads) {
                $socket = new-object Net.Sockets.UdpClient($ip.AddressFamily)
                $socket.Client.ReceiveTimeout = $timeout
                $socket.Connect($ip, $port)
                try {
                    $socket.Send($bytes, $bytes.Length) | out-null
                } catch {
                    $result["Status"] = "Closed"
                    $result["StatusColour"] = "DarkRed"
                    break
                }
                $endpoint = New-Object System.Net.IPEndPoint $ip, $port
                if ($banners) {
                    $result["Banner"] = ""
                }
                try {
                    $reply = $socket.Receive([ref]$endpoint)
                    $result["Status"] = "Open"
                    $result["StatusColour"] = "DarkGreen"
                    if ($banners) {
                        $result["Banner"] = $encoder.GetString($reply) -replace "`n"," " -replace "`r"," "
                    }
                    break
                } catch {
                    $result["Status"] = "Open|Filtered"
                    $result["StatusColour"] = "Yellow"
                }
                $socket.Close()
                Start-Sleep -Milliseconds $delay
            }
            $jsonBanner = "`"$($result["Banner"])`""
                    if ($result["Banner"].Trim() -eq "") {
                        $result["Banner"] = "<No Banner>"
                        $jsonBanner = "null"
                    }
        } else {
            # TCP connect scan
            $socket = new-object Net.Sockets.TcpClient($ip.AddressFamily)
            try {
                $socket.ConnectAsync($ip, $port).Wait($timeout) | out-null
            } catch {}
            if ($socket.Connected) {
                $result["Status"] = "Open"
                $result["StatusColour"] = "DarkGreen"
                if ($banners) {
                    Start-Sleep -seconds 1
                    $result["Banner"] = ""
                    $stream = $socket.GetStream()
                    while ($stream.DataAvailable) {
                        $byte = $stream.ReadByte()
                        $result["Banner"] = $encoder.GetString($byte) -replace "`n"," " -replace "`r"," "
                    }
                    $jsonBanner = "`"$($result["Banner"])`""
                    if ($result["Banner"].Trim() -eq "") {
                        $result["Banner"] = "<No Banner>"
                        $jsonBanner = "null"
                    }
                }
            } else {
                $result["Status"] = "Closed"
                $result["StatusColour"] = "DarkRed"
                if ($banners) {
                    $result["Banner"] = "<No Banner>"
                    $jsonBanner = "null"
                }
            }
            $socket.Close()
        }
        $result["Service"] = "Unknown"
        foreach ($service in $svcMap) {
            if (($service.Port -eq $port) -and ($service.Protocol -eq $protocol)) {
                if (($banners) -and ($result["Banner"].ToLower().contains($service.Service.ToLower()))) {
                        $result["Service"] = "$($service.Service)"
                } else {
                    $result["Service"] = "$($service.Service)?"
                }
                break
            }
        }
        if ($verbose) {
            writeOut -text $result["Status"] -foreground $result["StatusColour"]
        }
        writeJson -json "{" -level 4 -file $outJson
        writeJson -json "`"port`": $port," -level 5 -file $outJson
        writeJson -json "`"protocol`": `"$protocol`"," -level 5 -file $outJson
        writeJson -json "`"status`": `"$($result["Status"])`"," -level 5 -file $outJson
        if ($banners) {
            writeJson -json "`"service`": `"$($result["Service"])`"," -level 5 -file $outJson
            writeJson -json "`"banner`": $jsonBanner" -level 5 -file $outJson
        } else {
            writeJson -json "`"service`": `"$($result["Service"])`"" -level 5 -file $outJson
        }
        if ($port -eq $ports[-1]) {
            writeJson -json "}" -level 4 -file $outJson
        } else {
            writeJson -json "}," -level 4 -file $outJson
        }
        $results["$ip"]["Ports"] += $result
    }
    writeJson -json "]" -level 3 -file $outJson
    if ($ip -eq $targets[-1]) {
        writeJson -json "}" -level 2 -file $outJson
    } else {
        writeJson -json "}," -level 2 -file $outJson
    }
    $results["$ip"]["Ports"] = $results["$ip"]["Ports"] | Sort-Object {$_.Protocol}, {$_.Port}
    Start-Sleep -Milliseconds $delay
    $count += 1
    if ($verbose) {
        writeOut -text "Completed scan for $ip ($count/$numTargets)"
    }
}
writeJson -json "]," -level 1 -file $outJson
$results = $results | Sort-Object {$_.GetEnumerator().Name}


<###############################################################################
# Output Results                                                               #
###############################################################################>

writeOut -text "`nScan results:" -file $outTxt
foreach ($result in $results.GetEnumerator()) {
    writeOut -text $("_" * 80) -file $outTxt
    writeOut -text "`nHost:   $($result.Name)" -file $outTxt
    writeout -NoNewLine -text "Status: " -file $outTxt
    writeOut -text "$($result.Value["Status"])" -file $outTxt -foreground $result.Value["StatusColour"]
    if ($result.Value["Status"] -eq "Down") {
        writeOut -text "If you believe this host is up, rerun the scan using the -noPing (-nP) option to treat all hosts as up." -file $outTxt
        continue
    }
    writeOut -text "" -file $outTxt
    if ($banners) {
        $outTable = $result.Value["Ports"] | ForEach-Object {[PSCustomObject]$_} | Format-Table -AutoSize -Property @{L='Host'; E={$result.Name}}, @{L='Port'; E={"$($_.Port)/$($_.Protocol)"}}, "Status", "Service", "Banner"
    } else {
        $outTable = $result.Value["Ports"] | ForEach-Object {[PSCustomObject]$_} | Format-Table -AutoSize -Property @{L='Host'; E={$result.Name}}, @{L='Port'; E={"$($_.Port)/$($_.Protocol)"}}, "Status", "Service"
    }
    $outStr = "$($outTable | Out-String)".Trim()
    $fg = [System.Console]::ForegroundColor
    foreach($line in $outStr.Split([Environment]::NewLine)) {
        if ($line -eq "") {
            continue
        }
        if ($line -match "^\S+?\s+?\S+?\s+?Open\|Filtered.*?$") {
            $fg = "Yellow"
        } elseif ($line -match "^\S+?\s+?\S+?\s+?Open.*?$") {
            $fg = "DarkGreen"
        } elseif ($line -match "^\S+?\s+?\S+?\s+?Closed.*?$") {
            $fg = "DarkRed"
        }
        writeOut -text $line -file $outTxt -foreground $fg
    }
    if ($traceroute) {
        writeOut -text "`nTraceroute:`n" -file $outTxt
        $trTable = "$($result.Value["Traceroute"] | ForEach-Object {[PSCustomObject]$_} | Sort-Object Hop | Format-Table -AutoSize -Property "Hop", "Host" | Out-String)".Trim()
        foreach($line in $trTable.Split([Environment]::NewLine)) {
            if ($line -eq "") {
            continue
        }
            writeOut -text "    $line" -file $outTxt
        }
    }
}
writeOut -text $("_" * 80) -file $outTxt
$endTime = Get-Date
$scanDur = New-TimeSpan -start $startTime -End $endTime
$scanDurStr = $scanDur.ToString("dd'd 'hh'h 'mm'm 'ss's'")
writeJson -json "`"endTime`": `"$endTime`"," -level 1 -file $outJson
writeJson -json "`"duration`": `"$scanDurStr`"" -level 1 -file $outJson
writeJson -json "}" -level 0 -file $outJson
writeOut -text "`nScan completed at: $endTime (Duration: $scanDurStr)" -file $outTxt -NoNewLine
writeOut -text "" # New line in terminal but not in output file

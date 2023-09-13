# PS2
A port scanner written purely in PowerShell.

# Disclaimer
This tool was designed for legal purposes only; users are responsible for ensuring that their use of this tool complies with all appliable laws. By using this tool, you take full responsibility for any actions you perform. Neither NCC Group nor the author accept any liability for damage caused by the use of this tool.

# Usage
```
SYNTAX
    ps2.ps1 [-banners] [-delay <Int32>] [-inFiles <FileInfo[]>] [-hostnames <String[]>] [-ips <String[]>]      
    [-serviceMap <FileInfo>] [-noColour] [-noPing] [-overwrite] [-outAll <FileInfo>] [-outJson <FileInfo>]
    [-outTxt <FileInfo>] [-ports <Int32[]>] [-quick] [-randomise] [-timeout <Int32>] [-topPorts <Int32>]
    [-traceroute] -udp [-v]

    ps2.ps1 [-banners] [-delay <Int32>] [-inFiles <FileInfo[]>] [-hostnames <String[]>] [-ips <String[]>]      
    [-serviceMap <FileInfo>] [-noColour] [-noPing] [-overwrite] [-outAll <FileInfo>] [-outJson <FileInfo>]
    [-outTxt <FileInfo>] [-ports <Int32[]>] [-quick] [-randomise] [-timeout <Int32>] [-topPorts <Int32>]
    [-traceroute] -tcp [-v]

    ps2.ps1 [-delay <Int32>] [-inFiles <FileInfo[]>] [-hostnames <String[]>] [-ips <String[]>] [-noColour]     
    [-overwrite] [-outAll <FileInfo>] [-outJson <FileInfo>] [-outTxt <FileInfo>] [-randomise]
    [-timeout <Int32>] [-traceroute] -ping [-v]

    ps2.ps1 -help

PARAMETERS
    -banners [<SwitchParameter>]
        (-b) Attempt to grab banners from open ports

    -delay <Int32>
        (-d) Delay to use between each connection in milliseconds

    -inFiles <FileInfo[]>
        (-f) File(s) containing targets to scan (1 per line)

    -help [<SwitchParameter>]
        (-h) Displays help information

    -hostnames <String[]>
        (-n) Hostname(s) of target(s) to scan

    -ips <String[]>
        (-i) IP address(es) of target(s) to scan (supports individual IPv4 addresses, IPv4 address ranges,
        IPv4 CIDR notation, and individual IPv6 addresses)   

    -serviceMap <FileInfo>
        (-m) Service map to use (overrides default of <PS2_dir>/servicemap.csv)

    -noColour [<SwitchParameter>]
        (-nC) Do not use colour in terminal output

    -noPing [<SwitchParameter>]
        (-nP) Assume all hosts are up and do not ping them prior to scanning

    -overwrite [<SwitchParameter>]
        (-o) Force output files to be overwritten if they exist and do not prompt for confirmation

    -outAll <FileInfo>
        (-oA) Save output in txt and JSON formats to files with a specified name (supersedes -oJ and -oT
        options)

    -outJson <FileInfo>
        (-oJ) Save output in JSON format to a specified file

    -outTxt <FileInfo>
        (-oT) Save output in txt format to a specified file

    -ports <Int32[]>
        (-p) Port(s) to scan [supports PowerShell ranges e.g. use "-p (1..65535)" to scan all ports] (overrides default of top 1000 commonly used ports)

    -quick [<SwitchParameter>]
        (-q) Scan only the top 100 most commonly used ports

    -randomise [<SwitchParameter>]
        (-r) Randomise the order in which hosts and ports are scanned

    -timeout <Int32>
        (-t) Timeout to use for connections in milliseconds (overrides default of 1000ms)

    -topPorts <Int32>
        Scan the top n most commonly used ports (maximum 1000)

    -traceroute [<SwitchParameter>]
        Trace hop path to each host

    -ping [<SwitchParameter>]
        (-sP) Perform a ping scan

    -tcp [<SwitchParameter>]
        (-sT) Perform a TCP connect scan

    -udp [<SwitchParameter>]
        (-sU) Perform a UDP scan

    -v [<SwitchParameter>]
        (-Verbose, -vb) Show verbose output
```
# Service Maps
Service maps are used to define which services are known to run on which ports.

PS2 will work without a service map, however, it will not be able to provide service information without one.

By default, PS2 looks for  `servicemap.csv` in the same directory as `ps2.ps1`, however, this can be overwritten using the `-serviceMap` or `-m` parameters.

The service map file included in this repository was generated on a Kali Linux machine using the following command:

```
sed '/^#/d' /usr/share/nmap/nmap-services | sed '/^unknown\s/d' | cut -f 1,2 --output-delimiter "," | cut -d '/' -f 1,2 --output-delimiter "," | grep -P ',tcp$|,udp$' | unix2dos > servicemap.csv
```

# Compatibility
PS2 should be compatible with PowerShell version 5.1 and above.

# Credits
The UDP payloads were taken from [udp-proto-scanner](https://github.com/CiscoCXSecurity/udp-proto-scanner).

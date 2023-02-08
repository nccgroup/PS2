<#
.SYNOPSIS
A port scanner written purely in PowerShell
.Description
A port scanner written purely in PowerShell

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by James Conlan, James.Conlan@nccgroup.com

https://github.com/nccgroup/PS2

You should have received a copy of the GNU General Public License along with 
PS2. If not, see https://www.gnu.org/licenses.

This tool was designed for legal purposes only; users are responsible for
ensuring that their use of this tool complies with all appliable laws. By using
this tool, you take full responsibility for any actions you perform. Neither NCC
Group nor the author accept any liability for damage caused by the use of this
tool.
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
(-p) Port(s) to scan (overrides default of top 1000 commonly used ports)
.PARAMETER quick
(-q) Scan only the top 100 most commonly used ports
.PARAMETER randomise
(-r) Randomise the order in which hosts and ports are scanned
.PARAMETER timeout
(-t) Timeout to use for connections in milliseconds (overrides default of 1000ms)
.PARAMETER topPorts
Scan the top n most commonly used ports (maximum 1000)
.PARAMETER traceroute
Trace hop path to each host
.PARAMETER ping
(-sP) Perform a ping scan
.PARAMETER tcp
(-sT) Perform a TCP connect scan
.PARAMETER udp
(-sU) Perform a UDP scan
.PARAMETER v
(-Verbose, -vb) Show verbose output
#>


<###############################################################################
# CLI Parameters                                                               #
###############################################################################>

[cmdletbinding()]
param([Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][alias("b")][switch] $banners,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("d")][int] $delay,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("f")][System.IO.FileInfo[]] $inFiles,
      [Parameter(Mandatory=$true, ParameterSetName="help")][alias("h")][switch] $help,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("n")][string[]] $hostnames,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("i")][string[]] $ips,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][alias("m")][System.IO.FileInfo] $serviceMap,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("nC")][switch] $noColour,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][alias("nP")][switch] $noPing,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("o")][switch] $overwrite,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("oA")][System.IO.FileInfo] $outAll,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("oJ")][System.IO.FileInfo] $outJson,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("oT")][System.IO.FileInfo] $outTxt,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][alias("p")][int[]][ValidateRange(0, 65535)] $ports,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][alias("q")][switch] $quick,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("r")][switch] $randomise,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][alias("t")][int][ValidateRange(0, [int]::MaxValue)] $timeout,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][int][ValidateRange(1, 1000)] $topPorts,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][switch] $traceroute,
      [Parameter(Mandatory=$true, ParameterSetName="ping")][alias("sP")][switch] $ping,
      [Parameter(Mandatory=$true, ParameterSetName="tcp")][alias("sT")][switch] $tcp,
      [Parameter(Mandatory=$true, ParameterSetName="udp")][alias("sU")][switch] $udp,
      [Parameter(Mandatory=$false, ParameterSetName="tcp")][Parameter(Mandatory=$false, ParameterSetName="udp")][Parameter(Mandatory=$false, ParameterSetName="ping")][switch] $v
     )


<###############################################################################
# Config                                                                       #
###############################################################################>

$defDelay = 0
$defTimeout = 1000
$defSvcMap = "$(Split-Path $MyInvocation.MyCommand.Path)\servicemap.csv"
$topTcpPorts = @(
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
    2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
    1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1049, 1048, 2967,
    1053, 3703, 1056, 1065, 1064, 1054, 17, 808, 3689, 1031, 1044, 1071, 5901, 100, 9102, 8010, 2869, 1039, 5120, 4001,
    9000, 2105, 636, 1038, 2601, 1, 7000, 1066, 1069, 625, 311, 280, 254, 4000, 1761, 5003, 2002, 2005, 1998, 1032,
    1050, 6112, 3690, 1521, 2161, 6002, 1080, 2401, 4045, 902, 7937, 787, 1058, 2383, 32771, 1033, 1040, 1059, 50000, 5555,
    10001, 1494, 593, 2301, 3, 3268, 7938, 1234, 1022, 1074, 8002, 1036, 1035, 9001, 1037, 464, 497, 1935, 6666, 2003,
    6543, 1352, 24, 3269, 1111, 407, 500, 20, 2006, 3260, 15000, 1218, 1034, 4444, 264, 2004, 33, 1042, 42510, 999,
    3052, 1023, 1068, 222, 7100, 888, 563, 1717, 2008, 992, 32770, 32772, 7001, 8082, 2007, 5550, 2009, 5801, 1043, 512,
    2701, 7019, 50001, 1700, 4662, 2065, 2010, 42, 9535, 2602, 3333, 161, 5100, 5002, 2604, 4002, 6059, 1047, 8192, 8193,
    2702, 6789, 9595, 1051, 9594, 9593, 16993, 16992, 5226, 5225, 32769, 3283, 1052, 8194, 1055, 1062, 9415, 8701, 8652, 8651,
    8089, 65389, 65000, 64680, 64623, 55600, 55555, 52869, 35500, 33354, 23502, 20828, 1311, 1060, 4443, 1067, 13782, 5902, 366, 9050,
    1002, 85, 5500, 5431, 1864, 1863, 8085, 51103, 49999, 45100, 10243, 49, 6667, 90, 27000, 1503, 6881, 1500, 8021, 340,
    5566, 8088, 2222, 9071, 8899, 6005, 9876, 1501, 5102, 32774, 32773, 9101, 5679, 163, 648, 146, 1666, 901, 83, 9207,
    8001, 8083, 8084, 5004, 3476, 5214, 14238, 12345, 912, 30, 2605, 2030, 6, 541, 8007, 3005, 4, 1248, 2500, 880,
    306, 4242, 1097, 9009, 2525, 1086, 1088, 8291, 52822, 6101, 900, 7200, 2809, 800, 32775, 12000, 1083, 211, 987, 705,
    20005, 711, 13783, 6969, 3071, 5269, 5222, 1085, 1046, 5987, 5989, 5988, 2190, 3301, 11967, 8600, 3766, 7627, 8087, 30000,
    9010, 7741, 14000, 3367, 1099, 1098, 3031, 2718, 6580, 15002, 4129, 6901, 3827, 3580, 2144, 9900, 8181, 3801, 1718, 2811,
    9080, 2135, 1045, 2399, 3017, 10002, 1148, 9002, 8873, 2875, 9011, 5718, 8086, 3998, 2607, 11110, 4126, 9618, 2381, 1096,
    3300, 3351, 1073, 8333, 3784, 5633, 15660, 6123, 3211, 1078, 5910, 5911, 3659, 3551, 2260, 2160, 2100, 16001, 3325, 3323,
    1104, 9968, 9503, 9502, 9485, 9290, 9220, 8994, 8649, 8222, 7911, 7625, 7106, 65129, 63331, 6156, 6129, 60020, 5962, 5961,
    5960, 5959, 5925, 5877, 5825, 5810, 58080, 57294, 50800, 50006, 50003, 49160, 49159, 49158, 48080, 40193, 34573, 34572, 34571, 3404,
    33899, 32782, 32781, 31038, 30718, 28201, 27715, 25734, 24800, 22939, 21571, 20221, 20031, 19842, 19801, 19101, 17988, 1783, 16018, 16016,
    15003, 14442, 13456, 10629, 10628, 10626, 10621, 10617, 10616, 10566, 10025, 10024, 10012, 1169, 5030, 5414, 1057, 6788, 1947, 1094,
    1075, 1108, 4003, 1081, 1093, 4449, 1687, 1840, 1100, 1063, 1061, 1107, 1106, 9500, 20222, 7778, 1077, 1310, 2119, 2492,
    1070, 20000, 8400, 1272, 6389, 7777, 1072, 1079, 1082, 8402, 89, 691, 1001, 32776, 1999, 212, 2020, 6003, 7002, 2998,
    50002, 3372, 898, 5510, 32, 2033, 99, 749, 425, 5903, 43, 5405, 6106, 13722, 6502, 7007, 458, 9666, 8100, 3737,
    5298, 1152, 8090, 2191, 3011, 1580, 9877, 5200, 3851, 3371, 3370, 3369, 7402, 5054, 3918, 3077, 7443, 3493, 3828, 1186,
    2179, 1183, 19315, 19283, 3995, 5963, 1124, 8500, 1089, 10004, 2251, 1087, 5280, 3871, 3030, 62078, 5904, 9091, 4111, 1334,
    3261, 2522, 5859, 1247, 9944, 9943, 9110, 8654, 8254, 8180, 8011, 7512, 7435, 7103, 61900, 61532, 5922, 5915, 5822, 56738,
    55055, 51493, 50636, 50389, 49175, 49165, 49163, 3546, 32784, 27355, 27353, 27352, 24444, 19780, 18988, 16012, 15742, 10778, 4006, 2126,
    4446, 3880, 1782, 1296, 9998, 9040, 32779, 1021, 32777, 2021, 32778, 616, 666, 700, 5802, 4321, 545, 1524, 1112, 49400,
    84, 38292, 2040, 32780, 3006, 2111, 1084, 1600, 2048, 2638, 9111, 6699, 16080, 6547, 6007, 1533, 5560, 2106, 1443, 667,
    720, 2034, 555, 801, 6025, 3221, 3826, 9200, 2608, 4279, 7025, 11111, 3527, 1151, 8200, 8300, 6689, 9878, 10009, 8800,
    5730, 2394, 2393, 2725, 5061, 6566, 9081, 5678, 5906, 3800, 4550, 5080, 1201, 3168, 3814, 1862, 1114, 6510, 3905, 8383,
    3914, 3971, 3809, 5033, 7676, 3517, 4900, 3869, 9418, 2909, 3878, 8042, 1091, 1090, 3920, 6567, 1138, 3945, 1175, 10003,
    3390, 5907, 3889, 1131, 8292, 5087, 1119, 1117, 4848, 7800, 16000, 3324, 3322, 5221, 4445, 9917, 9575, 9099, 9003, 8290,
    8099, 8093, 8045, 7921, 7920, 7496, 6839, 6792, 6779, 6692, 6565, 60443, 5952, 5950, 5862, 5850, 5815, 5811, 57797, 56737,
    5544, 55056, 5440, 54328, 54045, 52848, 52673, 50500, 50300, 49176, 49167, 49161, 44501, 44176, 41511, 40911, 32785, 32783, 30951, 27356,
    26214, 25735, 19350, 18101, 18040, 17877, 16113, 15004, 14441, 12265, 12174, 10215, 10180, 4567, 6100, 4004, 4005, 8022, 9898, 7999,
    1271, 1199, 3003, 1122, 2323, 4224, 2022, 617, 777, 417, 714, 6346, 981, 722, 1009, 4998, 70, 1076, 5999, 10082,
    765, 301, 524, 668, 2041, 6009, 1417, 1434, 259, 44443, 1984, 2068, 7004, 1007, 4343, 416, 2038, 6006, 109, 4125,
    1461, 9103, 911, 726, 1010, 2046, 2035, 7201, 687, 2013, 481, 125, 6669, 6668, 903, 1455, 683, 1011, 2043, 2047,
    256, 9929, 5998, 406, 31337, 44442, 783, 843, 2042, 2045, 4040, 6060, 6051, 1145, 3916, 9443, 9444, 1875, 7272, 4252,
    4200, 7024, 1556, 13724, 1141, 1233, 8765, 1137, 3963, 5938, 9191, 3808, 8686, 3981, 2710, 3852, 3849, 3944, 3853, 9988,
    1163, 4164, 3820, 6481, 3731, 5081, 40000, 8097, 4555, 3863, 1287, 4430, 7744, 1812, 7913, 1166, 1164, 1165, 8019, 10160,
    4658, 7878, 3304, 3307, 1259, 1092, 7278, 3872, 10008, 7725, 3410, 1971, 3697, 3859, 3514, 4949, 4147, 7900, 5353, 3931
) # Top 1000 TCP ports
$topUdpPorts = @(
    631, 161, 137, 123, 138, 1434, 445, 135, 67, 53, 139, 500, 68, 520, 1900, 4500, 514, 49152, 162, 69,
    5353, 111, 49154, 1701, 998, 996, 997, 999, 3283, 49153, 1812, 136, 2222, 2049, 32768, 5060, 1025, 1433, 3456, 80,
    20031, 1026, 7, 1646, 1645, 593, 518, 2048, 626, 1027, 177, 1719, 427, 497, 4444, 1023, 65024, 19, 9, 49193,
    1029, 49, 88, 1028, 17185, 1718, 49186, 2000, 31337, 49201, 49192, 515, 2223, 443, 49181, 1813, 120, 158, 49200, 3703,
    32815, 17, 5000, 32771, 33281, 1030, 1022, 623, 32769, 5632, 10000, 49194, 49191, 49182, 49156, 9200, 30718, 49211, 49190, 49188,
    49185, 5001, 5355, 32770, 37444, 34861, 34555, 1032, 4045, 3130, 1031, 49196, 49158, 37, 2967, 4000, 989, 3659, 4672, 34862,
    23, 49195, 49189, 49187, 49162, 2148, 41524, 10080, 32772, 407, 42, 33354, 1034, 49199, 49180, 3389, 1001, 6346, 21, 13,
    517, 1068, 990, 1045, 1041, 6001, 1782, 19283, 49210, 49209, 49208, 49205, 49202, 49184, 49179, 49171, 9876, 39213, 800, 389,
    464, 1039, 1036, 1038, 1419, 192, 199, 44968, 1008, 49166, 49159, 1033, 1024, 22986, 19682, 22, 2002, 1021, 11487, 664,
    58002, 49172, 49168, 49165, 49163, 1043, 1885, 1049, 5093, 1044, 3052, 6000, 7938, 1019, 5351, 683, 5500, 27892, 16680, 32773,
    41058, 35777, 113, 52225, 49174, 49169, 49160, 1056, 1047, 8193, 685, 1886, 686, 6004, 38293, 782, 786, 38037, 32774, 780,
    1080, 32775, 682, 2051, 1054, 9950, 983, 6971, 6970, 1014, 1066, 5050, 781, 31891, 31681, 31073, 30365, 30303, 29823, 28547,
    27195, 25375, 22996, 22846, 21383, 20389, 20126, 20019, 19616, 19503, 19120, 18449, 16947, 16832, 42172, 33355, 32779, 53571, 52503, 49215,
    49213, 49212, 49204, 49198, 49175, 49167, 5002, 27015, 5003, 7000, 513, 1485, 1065, 1048, 1090, 684, 9103, 1037, 1761, 32777,
    539, 767, 434, 54321, 3401, 112, 6347, 512, 1000, 363, 47624, 42508, 45441, 41370, 41081, 40915, 40732, 40708, 40441, 40116,
    39888, 36206, 35438, 34892, 34125, 33744, 32931, 32818, 38, 776, 32776, 64513, 63555, 62287, 61370, 58640, 58631, 56141, 54281, 51717,
    50612, 49503, 49207, 49197, 49176, 49173, 49170, 49161, 49157, 1012, 217, 775, 3702, 8001, 9020, 1042, 902, 643, 829, 1040,
    1035, 1064, 1901, 688, 2160, 959, 9199, 8181, 1069, 687, 32528, 32385, 32345, 31731, 31625, 31365, 31195, 31189, 31109, 31059,
    30975, 30704, 30697, 30656, 30544, 30263, 29977, 29810, 29256, 29243, 29078, 28973, 28840, 28641, 28543, 28493, 28465, 28369, 28122, 27899,
    27707, 27482, 27473, 26966, 26872, 26720, 26415, 26407, 25931, 25709, 25546, 25541, 25462, 25337, 25280, 25240, 25157, 24910, 24854, 24644,
    24606, 24594, 24511, 24279, 24007, 23980, 23965, 23781, 23679, 23608, 23557, 23531, 23354, 23176, 23040, 22914, 22799, 22739, 22695, 22692,
    22341, 22055, 21902, 21803, 21621, 21354, 21298, 21261, 21212, 21131, 20359, 20004, 19933, 19687, 19600, 19489, 19332, 19322, 19294, 19197,
    19165, 19130, 19039, 19017, 18980, 18835, 18582, 18360, 18331, 18234, 18004, 17989, 17939, 17888, 17616, 17615, 17573, 17459, 17455, 17091,
    16918, 16430, 16402, 25003, 1346, 20, 2, 32780, 1214, 772, 1993, 402, 773, 31335, 774, 6050, 1046, 3664, 1057, 903,
    1053, 1081, 2343, 1100, 8000, 1234, 1124, 1105, 9001, 1804, 9000, 1050, 6002, 9877, 965, 838, 814, 8010, 1007, 1060,
    1055, 1524, 1059, 5555, 5010, 32778, 27444, 47808, 48761, 48489, 48455, 48255, 48189, 48078, 47981, 47915, 47772, 47765, 46836, 46532,
    46093, 45928, 45818, 45722, 45685, 45380, 45247, 44946, 44923, 44508, 44334, 44253, 44190, 44185, 44179, 44160, 44101, 43967, 43824, 43686,
    43514, 43370, 43195, 43094, 42639, 42627, 42577, 42557, 42434, 42431, 42313, 42056, 41971, 41967, 41896, 41774, 41702, 41638, 41446, 41308,
    40866, 40847, 40805, 40724, 40711, 40622, 40539, 40019, 39723, 39714, 39683, 39632, 39217, 38615, 38498, 38412, 38063, 37843, 37813, 37783,
    37761, 37602, 37393, 37212, 37144, 36945, 36893, 36778, 36669, 36489, 36458, 36384, 36108, 35794, 35702, 34855, 34796, 34758, 34580, 34579,
    34578, 34577, 34570, 34433, 34422, 34358, 34079, 34038, 33872, 33866, 33717, 33459, 33249, 33030, 32798, 1484, 3, 1067, 64727, 64590,
    64481, 64080, 63420, 62958, 62699, 62677, 62575, 62154, 61961, 61685, 61550, 61481, 61412, 61322, 61319, 61142, 61024, 60423, 60381, 60172,
    59846, 59765, 59207, 59193, 58797, 58419, 58178, 58075, 57977, 57958, 57843, 57813, 57410, 57409, 57172, 55587, 55544, 55043, 54925, 54807,
    54711, 54114, 54094, 53838, 53589, 53037, 53006, 52144, 51972, 51905, 51690, 51586, 51554, 51456, 51255, 50919, 50708, 50497, 50164, 50099,
    49968, 49640, 49396, 49393, 49360, 49350, 49306, 49262, 49259, 49226, 49222, 49220, 49216, 49214, 49178, 49177, 49155, 1058, 4666, 3457,
    559, 1455, 4008, 207, 764, 1457, 1200, 657, 3296, 1101, 689, 639, 3343, 8900, 1070, 1087, 1088, 1072, 2161, 944,
    9370, 826, 789, 16086, 1020, 1013, 1051, 2362, 2345, 502, 21800, 21847, 30260, 19315, 19541, 21000, 27007, 27002, 24242, 17754,
    20003, 17219, 18888, 32760, 32750, 32727, 32611, 32607, 32546, 32506, 32499, 32495, 32479, 32469, 32446, 32430, 32425, 32422, 32415, 32404,
    32382, 32368, 32359, 32352, 32326, 32273, 32262, 32219, 32216, 32185, 32132, 32129, 32124, 32066, 32053, 32044, 31999, 31963, 31918, 31887,
    31882, 31852, 31803, 31794, 31792, 31783, 31750, 31743, 31735, 31732, 31720, 31692, 31673, 31609, 31602, 31599, 31584, 31569, 31560, 31521,
    31520, 31481, 31428, 31412, 31404, 31361, 31352, 31350, 31343, 31334, 31284, 31267, 31266, 31261, 31202, 31199, 31180, 31162, 31155, 31137,
    31134, 31133, 31115, 31112, 31084, 31082, 31051, 31049, 31036, 31034, 30996, 30943, 30932, 30930, 30909, 30880, 30875, 30869, 30856, 30824,
    30803, 30789, 30785, 30757, 30698, 30669, 30661, 30622, 30612, 30583, 30578, 30533, 30526, 30512, 30477, 30474, 30473, 30465, 30461, 30348,
    30299, 30256, 30214, 30209, 30154, 30134, 30093, 30085, 30067, 30055, 30034, 29981, 29964, 29961, 29894, 29886, 29843, 29834, 29794, 29709,
    29613, 29595, 29581, 29564, 29554, 29541, 29534, 29522, 29503, 29461, 29453, 29449, 29444, 29426, 29410, 29401, 29400, 29357, 29333, 29319,
    29276, 29230, 29200, 29180, 29168, 29162, 29153, 29150, 29142, 29135, 29129, 29082, 29054, 29048, 29030, 28995, 28965, 28944, 28933, 28931,
    28892, 28815, 28808, 28803, 28746, 28745, 28725, 28719, 28707, 28706, 28692, 28674, 28664, 28663, 28645, 28640, 28630, 28609, 28584, 28525,
    28485, 28476, 28445, 28440, 28438, 28387, 28349, 28344, 28295, 28263, 28247, 28222, 28220, 28211, 28190, 28172, 28129, 28107, 28105, 28098,
    28091, 28080, 28071, 28070, 28034, 28011, 27973, 27969, 27949, 27919, 27895, 27861, 27853, 27750, 27722, 27718, 27711, 27708, 27696, 27682,
    27678, 27673, 27666, 27606, 27600, 27579, 27573, 27561, 27547, 27538, 27487, 27466, 27437, 27416, 27414, 27287, 27272, 27271, 27263, 27209
) # Top 1000 UDP ports
$udpPayloads = @{}
$udpPayloads[7] = @() +
                  ,[byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[11] = @() +
                   ,[byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[13] = @() +
                   ,[byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[19] = @() +
                   ,[byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[37] = @() +
                   ,[byte[]] $('31','32','33' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[53] = @() +
                   ,[byte[]] $('00','00','10','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" }) +
                   ,[byte[]] $('00','06','01','00','00','01','00','00','00','00','00','00','07','76','65','72','73','69','6f','6e','04','62','69','6e','64','00','00','10','00','03'| foreach-object { invoke-expression "0x$_" })
$udpPayloads[69] = @() +
                   ,[byte[]] $('00','01','2f','65','74','63','2f','70','61','73','73','77','64','00','6e','65','74','61','73','63','69','69','00' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[111] = @() +
                    ,[byte[]] $('03','9b','65','42','00','00','00','00','00','00','00','02','00','0f','42','43','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" }) +
                    ,[byte[]] $('72','FE','1D','13','00','00','00','00','00','00','00','02','00','01','86','A0','00','01','97','7C','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[123] = @() +
                    ,[byte[]] $('cb','00','04','fa','00','01','00','00','00','01','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','bf','be','70','99','cd','b3','40','00' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[137] = @() +
                    ,[byte[]] $('80','f0','00','10','00','01','00','00','00','00','00','00','20','43','4b','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','41','00','00','21','00','01' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[161] = @() +
                    ,[byte[]] $('30','82','00','2f','02','01','00','04','06','70','75','62','6c','69','63','a0','82','00','20','02','04','4c','33','a7','56','02','01','00','02','01','00','30','82','00','10','30','82','00','0c','06','08','2b','06','01','02','01','01','05','00','05','00' | foreach-object { invoke-expression "0x$_" }) +
                    ,[byte[]] $('30','3a','02','01','03','30','0f','02','02','4a','69','02','03','00','ff','e3','04','01','04','02','01','03','04','10','30','0e','04','00','02','01','00','02','01','00','04','00','04','00','04','00','30','12','04','00','04','00','a0','0c','02','02','37','f0','02','01','00','02','01','00','30','00'| foreach-object { invoke-expression "0x$_" })
$udpPayloads[177] = @() +
                    ,[byte[]] $('00','01','00','02','00','01','00','00' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[500] = @() +
                    ,[byte[]] $('5b','5e','64','c0','3e','99','b5','11','00','00','00','00','00','00','00','00','01','10','02','00','00','00','00','00','00','00','01','50','00','00','01','34','00','00','00','01','00','00','00','01','00','00','01','28','01','01','00','08','03','00','00','24','01','01' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[523] = @() +
                    ,[byte[]] $('44','42','32','47','45','54','41','44','44','52','00','53','51','4c','30','38','30','32','30' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[1434] = @() +
                     ,[byte[]] $('02' | foreach-object { invoke-expression "0x$_" }) +
                     ,[byte[]] $('0A' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[1604] = @() +
                     ,[byte[]] $('1e','00','01','30','02','fd','a8','e3','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[2123] = @() +
                     ,[byte[]] $('32','01','00','04','00','00','00','00','50','00','00','00' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[5405] = @() +
                     ,[byte[]] $('01','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','80','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" })
$udpPayloads[6502] = @() +
                     ,[byte[]] $('d6','81','81','52','00','00','00','f3','87','4e','01','02','32','00','a8','c0','00','00','01','13','c1','d9','04','dd','03','7d','00','00','0d','00','54','48','43','54','48','43','54','48','43','54','48','43','54','48','43','20','20','20','20','20','20','20','20','20','20','20','20','20','20','20','20','20','02','32','00','a8','c0','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00','00' | foreach-object { invoke-expression "0x$_" })


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

function saveJson {
    <#
    .SYNOPSIS
    Writes output to JSON file
    #>
    if ($outJson -and $jsonData) {
        $jsonData | ConvertTo-Json -Depth 5 | Out-File -FilePath $outJson
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

# Check for conflicting options
if ($quick -and $topPorts) {
    Throw "-q/-quick and -topPorts cannot be used in the same scan"
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
if (-Not $ping) {
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
if (-Not $ping) {
    if (-Not $ports) {
        $ports = @()
    }
    if (-Not $ports -and -Not $topPorts -and -Not $quick) {
        if ($udp) {
            $ports = $topUdpPorts
        } elseif ($tcp) {
            $ports = $topTcpPorts
        }
    }
    if ($quick) {
        if ($tcp) {
            $ports += $topTcpPorts | Select-Object -First 100
        } elseif ($udp) {
            $ports += $topUdpPorts | Select-Object -First 100
        }
    }
    if ($topPorts) {
        if ($tcp) {
            $ports += $topTcpPorts | Select-Object -First $topPorts
        } elseif ($udp) {
            $ports += $topUdpPorts | Select-Object -First $topPorts
        } 
    }
    $ports = $ports | Sort-Object -unique
    if ($randomise) {
        $ports = $ports | Sort-Object {Get-Random}
    }
}

# Set protocol
if ($tcp) {
    $protocol = "tcp"
} elseif ($udp) {
    $protocol = "udp"
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
    $jsonData = [ordered]@{"command" = $cmd}
    saveJson -file $outJson
}


<###############################################################################
# Scan                                                                         #
###############################################################################>

if ($tcp) {
    $scanType = "TCP"
} elseif ($udp) {
    $scanType = "UDP"
} elseif ($ping) {
    $scanType = "ping"
}
$jsonData.add("scanType", $scanType.ToLower())
$startTime = Get-Date
$jsonData.add("startTime", $startTime.ToString())
saveJson
if ($scanType) {
    writeOut -text "PS2 $scanType scan commenced at: $startTime" -file $outTxt
} else {
    writeOut -text "PS2 scan commenced at: $startTime" -file $outTxt
}
$results = @{}
$encoder = new-object system.text.asciiencoding
$jsonData.add("hosts", [hashtable[]]$())
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
    $hostJson = [ordered]@{"ip" = $($ip.IPAddressToString)}
    if (-Not $noPing) {
        # Ping host
        if ($verbose) {
            writeOut -NoNewLine -text "Pinging $($ip.IPAddressToString)... "
        }
        if ([version]$PSVersionTable.PSVersion -lt [version]"6.0.0") {
            try {
                $pingRes = Test-Connection $ip.IPAddressToString -Quiet
            } catch {
                $pingRes = $false
            }
        } else {
            $timeoutSecs = [int][math]::ceiling($timeout/1000)
            try {
                $pingRes = Test-Connection -TargetName $ip.IPAddressToString -TimeoutSeconds $timeoutSecs -Quiet
            } catch {
                $pingRes = $false
            }
        }
        $results["$ip"]["Status"] = "Up"
        $results["$ip"]["StatusColour"] = "DarkGreen"
        if ($verbose) {
            writeOut -text "Host is " -NoNewLine
        }
        if ($pingRes) {
            if ($verbose) {
                writeOut -text "up" -foreground "DarkGreen"
            }
            $hostJson.add("status", "up")
        } else {
            $results["$ip"]["Status"] = "Down"
            $results["$ip"]["StatusColour"] = "DarkRed"
            if ($verbose) {
                writeOut -text "down" -foreground "DarkRed"
            }
            $hostJson.add("status", "down")
            if ($traceroute) {
                $hostJson.add("traceroute", $null)
            }
            $hostJson.add("ports", $null)
            $jsonData["hosts"] += ,@($hostJson)
            saveJson
            continue
        }
    } else {
        if ($verbose) {
            writeOut -text "Assuming $($ip.IPAddressToString) host is up" -foreground "Yellow"
        }
        $results["$ip"]["Status"] = "Assumed Up"
        $results["$ip"]["StatusColour"] = "Yellow"
        $hostJson.add("status", "assumed up")
    }
    if ($traceroute) {
        # Traceroute
        if ($verbose) {
            writeOut -text "Performing traceroute for $ip... " -NoNewLine
        }
        $results["$ip"]["Traceroute"] = @()
        $hostJson.add("traceroute", @{})
        try {
            $Global:ProgressPreference = 'SilentlyContinue'
            $tr = Test-NetConnection -TraceRoute $ip -WarningAction:Stop 3>$null | Select-Object -ExpandProperty TraceRoute
            $Global:ProgressPreference = 'Continue'
            $trCount = 1
            foreach ($hop in $tr) {
                $hostJson["traceroute"].add("$trCount", $hop)
                $results["$ip"]["Traceroute"] += @{"Hop" = $trCount; "Host" = $hop}
                $trCount += 1
            }
            if ($verbose) {
                writeOut -text "Done" -foreground "DarkGreen"
            }
        } catch {
            $results["$ip"]["Traceroute"] += @{"Hop" = 0; "Host" = "Traceroute failed"}
            $hostJson["traceroute"].add("0", "traceroute failed")
            if ($verbose) {
                writeOut -text "Failed" -foreground "DarkRed"
            }
        }
    }
    if (-Not $ping) {
        $hostJson.add("ports", @())
        $numPorts = $ports.Length
        $portCount = 1
        foreach ($port in $ports) {
            $portJson = [ordered]@{}
            Start-Sleep -Milliseconds $delay
            if ($verbose) {
                writeOut -NoNewLine -text "Scanning $($ip.IPAddressToString) port $port/$protocol ($portCount/$numPorts)... "
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
                $payloads += , $encoder.GetBytes("$(Get-Date)")
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
                if ($banners) {
                    if ($result["Banner"].Trim() -eq "") {
                        $result["Banner"] = "<No Banner>"
                    }
                }
            } elseif ($tcp) {
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
                            $result["Banner"] += $encoder.GetString($byte) -replace "`n"," " -replace "`r"," "
                        }
                        if ($result["Banner"].Trim() -eq "") {
                            $result["Banner"] = "<No Banner>"
                        }
                    }
                } else {
                    $result["Status"] = "Closed"
                    $result["StatusColour"] = "DarkRed"
                    if ($banners) {
                        $result["Banner"] = "<No Banner>"
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
            $portJson.add("port", $port)
            $portJson.add("protocol", $protocol)
            $portJson.add("status", $result["Status"].ToLower())
            $portJson.add("service", $result["Service"])
            if ($banners) {
                $jsonBanner = $result["Banner"]
                if ($jsonBanner -eq "<No Banner>") {
                    $jsonBanner = $null
                }
                $portJson.add("banner", $jsonBanner)
            }
            $results["$ip"]["Ports"] += $result
            $hostJson["ports"] += $portJson
            $portCount += 1
        }
        $results["$ip"]["Ports"] = $results["$ip"]["Ports"] | Sort-Object {$_.Protocol}, {$_.Port}
        $hostJson["ports"] = $hostJson["ports"] | Sort-Object {$_.Protocol}, {$_.Port}
        Start-Sleep -Milliseconds $delay
    }
    $jsonData["hosts"] += ,@($hostJson)
    $jsonData["hosts"] = $jsonData["hosts"] | Sort-Object {try {[Version]$_["ip"]} catch {$_["ip"]}}
    saveJson
    $count += 1
    if ($verbose) {
        writeOut -text "Completed scan for $ip ($count/$numTargets)"
    }
}
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
        writeOut -text "If you believe this host is up, rerun the scan using the -nP/-noPing option to treat all hosts as up." -file $outTxt
        continue
    }
    if (-Not $ping) {
        writeOut -text "" -file $outTxt
    }
    if (-Not $ping) {
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
$jsonData.add("endTime", $endTime.ToString())
$jsonData.add("duration", $scanDurStr)
saveJson
writeOut -text "`nScan completed at: $endTime (Duration: $scanDurStr)" -file $outTxt -NoNewLine
writeOut -text "" # New line in terminal but not in output file

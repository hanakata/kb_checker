$wmi_OS_info = Get-WmiObject -ComputerName localhost -Class Win32_OperatingSystem;
$os = $wmi_OS_info.caption;
$bit = $wmi_OS_info.OSArchitecture;
$os_name = ""
$bit_value = ""

if($os.Contains("Windows 7")){
    $os_name = "Windows 7"
}
if($os.Contains("Windows 8")){
    $os_name = "Windows 8"
}
if($os.Contains("Windows 10")){
    $os_name = "Windows 10"
}
if($bit.Contains("32")){
    $bit_value = "32"
}
if($bit.Contains("64")){
    $bit_value = "64"
}

Write-Output $os_name
Write-Output $bit_value
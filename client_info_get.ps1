$filename = ".\check_list.txt"
$lines = get-content $filename
$username = Read-Host "input domain\username"
$pass = Read-Host "input password"
$password = $pass | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $password)
$kb_filename = ".\kb_info.csv"
$formatted_date = (Get-Date).ToString("yyyy-MM-dd")

$output = "PCname,logon_user,os,bit,status,kb,check_date"
Write-Output $output | Add-Content -Encoding utf8 $kb_filename

foreach ($server_info in $lines) {
    $server_address = $server_info.Split(",")
    $server_name = $server_address[0]
    $server_ip = $server_address[1]

    # if($server_ip -eq ""){
    #     $output = '"' + $server_name + '","","","","1","","'+ $formatted_date + '"'
    #     Write-Output $output | Add-Content -Encoding utf8 $kb_filename
    #     continue
    # }

    $wmi_OS_info = Get-WmiObject -ComputerName $server_name -Class Win32_OperatingSystem -Credential $credential;
    if ($? -ne "0") {
        $output = '"' + $server_name + '","","","","2","","' + $formatted_date + '"'
        Write-Output $output | Add-Content -Encoding utf8 $kb_filename
        continue
    }
    $os = $wmi_OS_info.caption;
    $bit = $wmi_OS_info.OSArchitecture;
    $os_name = ""
    $os_onfirm_flg = 0
    $os_not_r2_flg = 0
    $bit_value = ""
    $bit_flg = 0

    if ($os.Contains("Windows 7")) {
        $os_name = "Windows 7"
        $os_onfirm_flg = 1
    }
    if ($os.Contains("Windows 8" -And $os_onfirm_flg -eq 0)) {
        $os_name = "Windows 8"
        $os_onfirm_flg = 1
    }
    if ($os.Contains("Windows 10") -And $os_onfirm_flg -eq 0) {
        $os_name = "Windows 10"
        $os_onfirm_flg = 1
    }
    if ($os.Contains("2008 R2") -And $os_onfirm_flg -eq 0) {
        $os_name = "Windows Server 2008 R2"
        $os_onfirm_flg = 1
    }
    if ($os.Contains("2012 R2") -And $os_onfirm_flg -eq 0) {
        $os_name = "Windows Server 2012 R2"
        $bit_flg = 1
        $os_onfirm_flg = 1
    }
    if ($os.Contains("2016 R2") -And $os_onfirm_flg -eq 0) {
        $os_name = "Windows Server 2016 R2"
        $bit_flg = 1
        $os_onfirm_flg = 1
    }
    if ($os.Contains("2008") -And $os_onfirm_flg -eq 0) {
        $os_name = "Windows Server 2008"
        $os_onfirm_flg = 1
        $os_not_r2_flg = 1
    }
    if ($os.Contains("2012") -And $os_onfirm_flg -eq 0) {
        $os_name = "Windows Server 2012"
        $bit_flg = 1
        $os_onfirm_flg = 1
        $os_not_r2_flg = 1
    }
    if ($os.Contains("2016") -And $os_onfirm_flg -eq 0) {
        $os_name = "Windows Server 2016"
        $bit_flg = 1
        $os_onfirm_flg = 1
        $os_not_r2_flg = 1
    }
    if ($bit.Contains("32")) {
        $bit_value = "32"
    }
    if ($bit.Contains("64")) {
        $bit_value = "64"
    }

    $client_kb_list = @()
    $client_kb_info = Get-WMIObject -ComputerName $server_name Win32_QuickFixEngineering -Credential $credential
    $client_kb_list += $client_kb_info.HotFixID
    $client_kb_list = $client_kb_list | Sort-Object | Get-Unique

    $kb = '"'
    $n = 0
    foreach ($client_kb in $client_kb_list) {
        if ($n -eq 0) {
            $kb += $client_kb
            $n = 1            
        }
        else {
            $kb += ":" + $client_kb
        }
    }
    $kb += '"'

    $user_name = Get-WmiObject -ComputerName $server_name -Class Win32_ComputerSystem -Property UserName, Name -Credential $credential

    $output = '"' + $user_name.Name + '","' + $user_name.UserName + '","' + $os_name + '","' + $bit_value + '","' + '0",' + $kb + ',"' + $formatted_date + '"'
    Write-Output $output | Add-Content -Encoding utf8 $kb_filename
}
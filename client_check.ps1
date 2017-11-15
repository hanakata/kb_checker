function db_count_query($ConnectionString,$sql){
    $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
    $conn.Open()
    $command = New-Object MySql.Data.MySqlClient.MySqlCommand($sql, $conn)
    $count = $command.ExecuteScalar()
    $conn.Close()
    $conn.Dispose()
    $command.Dispose()
    return $count
}

$filename = ".\check_list.txt"
$lines = get-content $filename
$username = Read-Host "input domain\username"
$pass = Read-Host "input password"
$password = $pass | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

foreach($server_info in $lines){
    $server_address = $server_info.Split(",")
    $server_name = $server_address[0]
    $server_ip = $server_address[1]
    Write-Output "check:"$server_ip

    $kb_filename = ".\kb\" + $server_name + "_kb_info.csv"
    $cve_filename = ".\cve\" + $server_name + "_cve_info.csv"

    $wmi_OS_info = Get-WmiObject -ComputerName $server_ip -Class Win32_OperatingSystem -Credential $credential;
    $os = $wmi_OS_info.caption;
    $bit = $wmi_OS_info.OSArchitecture;
    $os_name = ""
    $os_onfirm_flg = 0
    $os_not_r2_flg = 0
    $bit_value = ""
    $bit_flg = 0


    if($os.Contains("Windows 7")){
        $os_name = "Windows 7"
        $os_onfirm_flg = 1
    }
    if($os.Contains("Windows 8" -And $os_onfirm_flg -eq 0)){
        $os_name = "Windows 8"
        $os_onfirm_flg = 1
    }
    if($os.Contains("Windows 10") -And $os_onfirm_flg -eq 0){
        $os_name = "Windows 10"
        $os_onfirm_flg = 1
    }
    if($os.Contains("2008 R2") -And $os_onfirm_flg -eq 0){
        $os_name = "Windows Server 2008 R2"
        $os_onfirm_flg = 1
    }
    if($os.Contains("2012 R2") -And $os_onfirm_flg -eq 0){
        $os_name = "Windows Server 2012 R2"
        $bit_flg = 1
        $os_onfirm_flg = 1
    }
    if($os.Contains("2016 R2") -And $os_onfirm_flg -eq 0){
        $os_name = "Windows Server 2016 R2"
        $bit_flg = 1
        $os_onfirm_flg = 1
    }
    if($os.Contains("2008") -And $os_onfirm_flg -eq 0){
        $os_name = "Windows Server 2008"
        $os_onfirm_flg = 1
        $os_not_r2_flg = 1
    }
    if($os.Contains("2012") -And $os_onfirm_flg -eq 0){
        $os_name = "Windows Server 2012"
        $bit_flg = 1
        $os_onfirm_flg = 1
        $os_not_r2_flg = 1
    }
    if($os.Contains("2016") -And $os_onfirm_flg -eq 0){
        $os_name = "Windows Server 2016"
        $bit_flg = 1
        $os_onfirm_flg = 1
        $os_not_r2_flg = 1
    }
    if($bit.Contains("32")){
        $bit_value = "32"
    }
    if($bit.Contains("64")){
        $bit_value = "64"
    }

    $client_kb_list = @()
    $client_kb_info = Get-WMIObject -ComputerName $server_ip Win32_QuickFixEngineering -Credential $credential
    $client_kb_list += $client_kb_info.HotFixID
    $client_kb_list = $client_kb_list | Sort-Object | Get-Unique

    $mysql_dll = "C:\Program Files (x86)\MySQL\Connector.NET 6.9\Assemblies\v4.5\MySql.Data.dll"
    $ConnectionString = "Server=10.51.5.112;Port=3306;User Id=root;Password=ppppp0!!;Database=kb_checker;"
    [reflection.assembly]::LoadFrom($mysql_dll)

    if($bit_flg -eq 1){
        $select_kb_list_sql = 'SELECT * FROM kb_list INNER JOIN production_list ON kb_list.producrion_id = production_list.production_id where production_name LIKE "%'+ $os_name +'%";'
    }else{
        $select_kb_list_sql = 'SELECT * FROM kb_list INNER JOIN production_list ON kb_list.producrion_id = production_list.production_id where production_name LIKE "%'+ $os_name +'%" AND production_name LIKE "%' + $bit_value + '%";'
    }
    
    $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
    $conn.Open()
    $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_kb_list_sql, $conn)
    $result = $command.ExecuteReader()
    $all_kb_list = @()
    while($result.Read()){
        if($os_not_r2_flg -ne 1){
            $all_kb_list += $result[2]
        }else{
            if(! $result[5].Contains("R2")){
                $all_kb_list += $result[2]
            }
        }
    }
    $conn.Close()
    $all_kb_list = $all_kb_list | Sort-Object | Get-Unique

    $compare_kb_all = Compare-Object $all_kb_list $client_kb_list
    $compare_inputobject_all = @()
    $compare_inputobject_all += $compare_kb_all.InputObject
    $compare_sideindicator_all = @()
    $compare_sideindicator_all = $compare_kb_all.SideIndicator
    $compare_kb = @()
    $i = 0
    foreach($compare_sideindicator in $compare_sideindicator_all){
        if($compare_sideindicator -eq "<="){
            $compare_kb += $compare_inputobject_all[$i]
        }
        $i = $i + 1
    }
    $cve_list = @()
    foreach($kb in $compare_kb){     
        $select_cve_info_sql = 'SELECT * FROM kb_list where kb_number = "' + $kb + '";'
        $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
        $conn.Open()
        $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_cve_info_sql, $conn)
        $result = $command.ExecuteReader()
        while($result.Read()){
            $cve_list += $result[1]
        }
        $conn.Close()
    }

    $cve_list = $cve_list | Sort-Object | Get-Unique

    foreach($kb in $compare_kb){
        if($bit_flg -eq 1){
            $select_kb_info_sql = 'SELECT * FROM kb_list INNER JOIN production_list ON kb_list.producrion_id = production_list.production_id where kb_number = "' + $kb + '" AND production_name LIKE "%'+ $os_name +'%";'
        }else{
            $select_kb_info_sql = 'SELECT * FROM kb_list INNER JOIN production_list ON kb_list.producrion_id = production_list.production_id where kb_number = "' + $kb + '" AND production_name LIKE "%'+ $os_name +'%" AND production_name LIKE "%' + $bit_value + '%";'
        }
        $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
        $conn.Open()
        $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_kb_info_sql, $conn)
        $result = $command.ExecuteReader()
        while($result.Read()){
            if($os_not_r2_flg -ne 1){
                $kb_list = '"' + $result[1] + '","' + $result[2] + '","' + $result[5] + '"'
                Write-Output $kb_list | Add-Content -Encoding utf8 $kb_filename
            }else{
                if(! $result[5].Contains("R2")){
                    $kb_list = '"' + $result[1] + '","' + $result[2] + '","' + $result[5] + '"'
                    Write-Output $kb_list | Add-Content -Encoding utf8 $kb_filename
                }
            }
        }
        $conn.Close()
    }

    foreach($cve_info in $cve_list){
        $n = 0
        $select_cve_count_sql = 'SELECT COUNT(*) FROM jvns where cve_id = "' + $cve_info + '";'
        $db_count = db_count_query $ConnectionString $select_cve_count_sql
        if( $db_count -ne 0){
            $select_cve_info_sql = 'SELECT * FROM jvns where cve_id = "' + $cve_info + '";'
            $n = 1
        }
        if($n -eq 0 ){
            $select_cve_count_sql = 'SELECT COUNT(*) FROM nvds where cve_id = "' + $cve_info + '";'
            $db_count = db_count_query $ConnectionString $select_cve_count_sql
            if( $db_count -ne 0){
                $select_cve_info_sql = 'SELECT * FROM nvds where cve_id = "' + $cve_info + '";'
                $n = 2
            }
        }
        if($n -eq 0 ){
            $select_cve_count_sql = 'SELECT COUNT(*) FROM cve_list where cve_number = "' + $cve_info + '";'
            $db_count = db_count_query $ConnectionString $select_cve_count_sql
            if( $db_count -ne 0){
                $select_cve_info_sql = 'SELECT * FROM cve_list where cve_number = "' + $cve_info + '";'
                Write-Output $select_cve_info_sql
                $n = 3
            }
        }

        $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
        $conn.Open()
        $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_cve_info_sql, $conn)
        $result = $command.ExecuteReader()
        while($result.Read()){
            if($n -eq 1){
                $cve = '"JVN","' + $result[5] + '","' + $result[7] + '","' + $result[10] + '","' + $result[11] + '","' + $result[13] + '"'
                Write-Output $cve | Add-Content -Encoding utf8 $cve_filename
            }
            if($n -eq 2){
                $cve = '"NVD","' + $result[5] + '","' + $result[6] + '","' + $result[7] + '","' + $result[9] + '","' + $result[15] + '"'
                Write-Output $cve | Add-Content -Encoding utf8 $cve_filename
            }
            if($n -eq 3){
                $cve = '"MS","' + $result[1] + '","' + $result[2] + '","' + $result[3] + '"'
                Write-Output $cve | Add-Content -Encoding utf8 $cve_filename
            }
        }
        $conn.Close()
    }
}
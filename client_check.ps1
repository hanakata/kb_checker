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

    $client_kb_list = @()
    $client_kb_info = Get-WMIObject -ComputerName $server_ip Win32_QuickFixEngineering -Credential $credential
    $client_kb_list += $client_kb_info.HotFixID
    $client_kb_list = $client_kb_list | Sort-Object | Get-Unique

    $mysql_dll = "C:\Program Files (x86)\MySQL\Connector.NET 6.9\Assemblies\v4.5\MySql.Data.dll"
    $ConnectionString = "Server=10.51.5.112;Port=3306;User Id=root;Password=ppppp0!!;Database=kb_checker;"
    [reflection.assembly]::LoadFrom($mysql_dll)

    $select_kb_list_sql = 'SELECT * FROM kb_list INNER JOIN production_list ON kb_list.producrion_id = production_list.production_id where production_name LIKE "%'+ $os_name +'%" AND production_name LIKE "%' + $bit_value + '%";'
    $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
    $conn.Open()
    $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_kb_list_sql, $conn)
    $result = $command.ExecuteReader()
    $all_kb_list = @()
    while($result.Read()){
        $all_kb_list += $result[2]
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

    foreach($kb in $compare_kb){
        $select_cve_info_sql = 'SELECT * FROM kb_list where kb_number = "' + $kb + '";'
        $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
        $conn.Open()
        $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_cve_info_sql, $conn)
        $result = $command.ExecuteReader()
        $cve_list = @()
        while($result.Read()){
            $cve_list += $result[1]
        }
        $conn.Close()
        $cve_list = $cve_list | Sort-Object | Get-Unique

        $select_kb_info_sql = 'SELECT * FROM kb_list INNER JOIN production_list ON kb_list.producrion_id = production_list.production_id where kb_number = "' + $kb + '" AND production_name LIKE "%'+ $os_name +'%" AND production_name LIKE "%' + $bit_value + '%";'
        $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
        $conn.Open()
        $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_kb_info_sql, $conn)
        $result = $command.ExecuteReader()
        $product_list = @()
        while($result.Read()){
            $product_list += $result[5]
        }
        $conn.Close()
        $product_list = $product_list | Sort-Object | Get-Unique
    }
    
    $n = 0
    foreach($cve_info in $cve_list){
        $select_cve_count_sql = 'SELECT COUNT(*) FROM jvns where cve_id = "' + $cve_info + '";'
        db_count_query $ConnectionString $select_cve_count_sql
        if( $_ -ne 0){
            $select_cve_info_sql = 'SELECT * FROM jvns where cve_id = "' + $cve_info + '";'
            $n = 1
        }
        if($n -eq 0 ){
            $select_cve_count_sql = 'SELECT COUNT(*) FROM nvds where cve_id = "' + $cve_info + '";'
            db_count_query $ConnectionString $select_cve_count_sql
            if( $_ -ne 0){
                $select_cve_info_sql = 'SELECT * FROM nvds where cve_id = "' + $cve_info + '";'
                $n = 2
            }
        }
        if($n -eq 0 ){
            $select_cve_count_sql = 'SELECT COUNT(*) FROM cve_list where cve_number = "' + $cve_info + '";'
            db_count_query $ConnectionString $select_cve_count_sql
            if( $_ -ne 0){
                $select_cve_info_sql = 'SELECT * FROM cve_list where cve_number = "' + $cve_info + '";'
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
                $cve = '"MS","' + $result[1] + '","' + $result[2] + '"'
                Write-Output $cve | Add-Content -Encoding utf8 $cve_filename
            }
        }
        $conn.Close()
    }
}
function db_run_query($ConnectionString, $sql) {
    $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
    $conn.Open()
    $command = New-Object MySql.Data.MySqlClient.MySqlCommand($sql, $conn)
    $result = $command.ExecuteNonQuery()
    if ($result -eq '-1') {
        Write-Output "Error"
    }
    $conn.Close()
    $conn.Dispose()
    $command.Dispose()
}

#Install-Module MSRCSecurityUpdates -Force
Import-module msrcsecurityupdates
Set-MSRCApiKey -ApiKey <<API_KEY>> -Verbose

$mysql_dll = "C:\Program Files (x86)\MySQL\Connector.NET 6.9\Assemblies\v4.5\MySql.Data.dll"
# $ConnectionString = "Server=localhost;Port=3306;User Id=root;Password=ppppp0!!;Database=kb_checker;Max Pool Size=300;"
$ConnectionString = "Server=localhost;Port=3306;User Id=root;Password=ppppp0!!;Database=kb_checker;"

[reflection.assembly]::LoadFrom($mysql_dll)

$tag_delete = "<('[^']*'|'[^']*'|[^''>])*>"
$update_info = Get-MsrcSecurityUpdate
$update_id_list = @()
$update_date_list = @()
$current_cve_list = @()
$current_production_list = @()
$update_id_list += $update_info.id
$update_date_list += $update_info.InitialReleaseDate

$delete_cve_list_sql = 'DELETE FROM cve_list;'
db_run_query $ConnectionString $delete_cve_list_sql
$delete_kb_list_sql = 'DELETE FROM kb_list;'
db_run_query $ConnectionString $delete_kb_list_sql
$delete_production_list_sql = 'DELETE FROM production_list;'
db_run_query $ConnectionString $delete_production_list_sql

$j = 0
foreach ($update_id in $update_id_list) {
    $kb_info_get = Get-MsrcCvrfDocument -ID $update_id -Verbose
    $cve_list = @()
    $cve_list += $kb_info_get.Vulnerability.CVE
    $update_date_tmp = $update_date_list[$j]
    $a = $update_date_tmp.Split("-")
    $update_date = $a[0] + "-" + $a[1]
    $insert_cve_list_sql = 'INSERT INTO cve_list VALUES '
    $insert_kb_list_sql = 'INSERT INTO kb_list VALUES '
    $insert_production_list_sql = 'INSERT INTO production_list VALUES '

    $n = 'off'
    $m = 'off'
    $s = 'off'
    foreach ($cve in $cve_list) {

        $cve_info = $kb_info_get.Vulnerability | Where-Object CVE -match $cve
        $note = $cve_info.Title.Value
        $MaximumSeverity = Switch (
            ($cve_info.Threats | Where-Object {$_.Type -eq 3 }).Description.Value | Select-Object -Unique
        ) {
            'Critical' { 'Critical'  ; break }
            'Important' { 'Important' ; break }
            'Moderate' { 'Moderate'  ; break }
            'Low' { 'Low'       ; break }
            default {
                'Unkwown'
            }
        }
        $cve_id = [Array]::IndexOf($current_cve_list, $cve)
        if ($cve_id -eq '-1') {
            $current_cve_list += $cve
            if ($n -eq 'off') {
                $insert_cve_list_sql = $insert_cve_list_sql + '("' + $update_id + '", "' + $cve + '", "' + $note + '", "' + $MaximumSeverity + '")'
                $n = 'on'
            }
            else {
                $insert_cve_list_sql = $insert_cve_list_sql + ',("' + $update_id + '", "' + $cve + '", "' + $note + '", "' + $MaximumSeverity + '")'
            }
        }
        $kb_info = $cve_info.Remediations | Where-Object Type -match "2"
        $kb_list = @()
        $kb_list += $kb_info.Description.Value
        $kb_list = $kb_list | Sort-Object | Get-Unique
        foreach ($kb_number in $kb_list) {
            $kb = "KB" + $kb_number
            $kb_production_id = $kb_info_get.Vulnerability.Remediations | Where-Object Description -match $kb_number
            $producrion_id_list = $kb_production_id.ProductID
            $producrion_id_list = $producrion_id_list | Sort-Object | Get-Unique
            foreach ($producrion_id in $producrion_id_list) {
                if ($m -eq 'off') {
                    $insert_kb_list_sql = $insert_kb_list_sql + '("' + $update_date + '", "' + $cve + '", "' + $kb + '", "' + $producrion_id + '")'
                    $m = 'on'
                }
                else {
                    $insert_kb_list_sql = $insert_kb_list_sql + ',("' + $update_date + '", "' + $cve + '", "' + $kb + '", "' + $producrion_id + '")'
                }
            }
        }
    }
    if ($n -eq 'on') {
        db_run_query $ConnectionString $insert_cve_list_sql        
    }
    if ($m -eq 'on') {
        db_run_query $ConnectionString $insert_kb_list_sql
    }
    $production_info = $kb_info_get.ProductTree.FullProductName
    $production_id_list = @()
    $production_name_list = @()
    $production_id_list += $production_info.ProductID
    $production_name_list += $production_info.Value
    $i = 0
    foreach ($production_id in $production_id_list) {
        $production_index = [Array]::IndexOf($current_production_list, $production_id)
        if ($production_index -eq '-1') {
            $current_production_list += $production_id
            if ($s -eq 'off') {
                $insert_production_list_sql = $insert_production_list_sql + '("' + $production_id + '", "' + $production_name_list[$i] + '")'
                $s = 'on'
            }
            else {
                $insert_production_list_sql = $insert_production_list_sql + ',("' + $production_id + '", "' + $production_name_list[$i] + '")'
            }
        }
        $i = $i + 1
    }
    $j = $j + 1
    if ($s -eq 'on') {
        db_run_query $ConnectionString $insert_production_list_sql
    }
}
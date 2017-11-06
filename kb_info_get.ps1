function db_connect($ConnectionString,$sql){
    $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
    $conn.Open()
    $command = New-Object MySql.Data.MySqlClient.MySqlCommand($sql, $conn)
    $command.ExecuteReader()
    $conn.Close()
}

Install-Module MSRCSecurityUpdates -Force
Import-module msrcsecurityupdates
Set-MSRCApiKey -ApiKey "" -Verbose

$mysql_dll = "C:\Program Files (x86)\MySQL\Connector.NET 6.9\Assemblies\v4.5\MySql.Data.dll"
$ConnectionString = "Server=localhost;Port=3306;User Id=root;Password=ppppp0!!;Database=kb_checker;"

[reflection.assembly]::LoadFrom($mysql_dll)

$tag_delete = "<('[^']*'|'[^']*'|[^''>])*>"
$update_info = Get-MsrcSecurityUpdate
$update_id_list = @()
$update_id_list += $update_info.id

$delete_cve_list_sql = 'DELETE FROM cve_list;'
db_connect $ConnectionString $delete_cve_list_sql
$delete_kb_list_sql = 'DELETE FROM kb_list;'
db_connect $ConnectionString $delete_kb_list_sql
$delete_production_list_sql = 'DELETE FROM production_list;'
db_connect $ConnectionString $delete_production_list_sql

foreach($update_id in $update_id_list){
    $kb_info_get = Get-MsrcCvrfDocument -ID $update_id -Verbose
    $cve_list = @()
    $cve_list += $kb_info_get.Vulnerability.CVE

    foreach($cve in $cve_list){
        $cve_info = $kb_info_get.Vulnerability | Where-Object CVE -match $cve
        $cve_description = $cve_info.Notes | Where-Object Type -match "2"
        $note = $cve_description.Value | % { $_ -replace $tag_delete, "" }
        $insert_cve_list_sql = 'INSERT INTO cve_list VALUES ("'+ $update_id+'", "'+$cve+'", "'+$note+'");'
        db_connect $ConnectionString $insert_cve_list_sql
        
        $kb_info = $cve_info.Remediations | Where-Object Type -match "2"
        $kb_list = @()
        $kb_list += $kb_info.Description.Value
        $kb_list = $kb_list | Sort-Object | Get-Unique
        foreach($kb_number in $kb_list){
            $kb = "KB" + $kb_number
            $kb_production_id = $kb_info_get.Vulnerability.Remediations | Where-Object Description -match $kb_number
            $producrion_id_list = $kb_production_id.ProductID
            $producrion_id_list = $producrion_id_list | Sort-Object | Get-Unique
            foreach($producrion_id in $producrion_id_list){
                $insert_kb_list_sql = 'INSERT INTO kb_list VALUES ("'+ $update_id+'", "'+$cve+'", "'+$kb+'", "'+$producrion_id+'");'
                db_connect $ConnectionString $insert_kb_list_sql
            }
        }
    }

    $production_info = $kb_info_get.ProductTree.FullProductName
    $production_id_list = @()
    $production_name_list = @()
    $production_id_list += $production_info.ProductID
    $production_name_list += $production_info.Value
    $i = 0
    foreach($production_id in $production_id_list){
        $replace_production_list_sql = 'replace INTO production_list VALUES ("'+ $production_id + '", "' + $production_name_list[$i] + '");'
        db_connect $ConnectionString $replace_production_list_sql
        $i = $i + 1
    }
}
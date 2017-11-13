$filename = ".\check_list.txt"
$lines = get-content $filename
$username = Read-Host "input domain\username"
$pass = Read-Host "input password"
$password = $pass | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

foreach($server_info in $lines){
    # $excel = New-Object -ComObject Excel.Application
    # $excel.Visible = $true
    # $excel.DisplayAlerts = $true
    # $book = $excel.Workbooks.Add()

    # $kb_sheet_name = $server + "_KB"
    # $book.Sheets(1).Name = $kb_sheet_name
    # $sheet = $book.Sheets($kb_sheet_name)
    $server_address = $server_info.Split(",")
    $server = $server_address[1]

    $wmi_OS_info = Get-WmiObject -ComputerName $server -Class Win32_OperatingSystem -Credential $credential;
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
    $client_kb_info = Get-WMIObject -ComputerName $server Win32_QuickFixEngineering -Credential $credential
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

    # $sheet.Cells.Item(1, 1) = "KB"
    # $sheet.Cells.Item(1, 2) = "CVE"
    # $sheet.Cells.Item(1, 3) = "product"
    # $x = 2

    foreach($kb in $compare_kb){
        # $sheet.Cells.Item($x, 1) = $kb
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
        # $excel_cve_number = ''
        # foreach($cve_number in $cve_list){
        #     $excel_cve_number += $cve_number + "`r`n"
        # }
        # $sheet.Cells.Item($x, 2) = $excel_cve_number

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
        # $excel_product_name = ''
        # foreach($product_name in $product_list){
        #     $excel_product_name += $product_name + "`r`n"
        # }
        # $sheet.Cells.Item($x, 3) = $excel_product_name
        # $x = $x + 1
    }
    # $sheet.Columns.AutoFit()

    $cve_info_list = @()
    foreach($kb in $compare_kb){
        $select_cve_info_sql = 'SELECT * FROM kb_list where kb_number = "' + $kb + '";'
        $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
        $conn.Open()
        $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_cve_info_sql, $conn)
        $result = $command.ExecuteReader()
        while($result.Read()){
            $cve_info_list += $result[1]
        }
        $conn.Close()
    }
    $cve_info_list = $cve_info_list | Sort-Object | Get-Unique
    # $book.Worksheets.Add() 
    # $cve_sheet_name = $server + "_cve"
    # $book.Sheets(1).Name = $cve_sheet_name
    # $sheet = $book.Sheets($cve_sheet_name)

    # $sheet.Cells.Item(1, 1) = "CVE"
    # $sheet.Cells.Item(1, 2) = "Note"
    # $x = 2

    foreach($cve_info in $cve_info_list){
        # $sheet.Cells.Item($x, 1) = $cve_info
        $select_cve_info_sql = 'SELECT * FROM cve_list where cve_number = "' + $cve_info + '";'
        $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
        $conn.Open()
        $command = New-Object MySql.Data.MySqlClient.MySqlCommand($select_cve_info_sql, $conn)
        $result = $command.ExecuteReader()
        while($result.Read()){
            Write-Output $result[2]
            # $sheet.Cells.Item($x, 2) = $result[2]
        }
        $conn.Close()
        # $x = $x + 1
    }

    # $sheet.Columns.AutoFit()

    # $book.SaveAs("${HOME}\Desktop\" + $server + ".xlsx")
    # $excel.Quit()

    # [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel)
    # [System.Runtime.Interopservices.Marshal]::ReleaseComObject($sheet)
}
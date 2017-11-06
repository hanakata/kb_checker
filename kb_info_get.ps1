Import-module msrcsecurityupdates
Set-MSRCApiKey -ApiKey "" -Verbose

$tag_delete = "<('[^']*'|'[^']*'|[^''>])*>"
$update_info = Get-MsrcSecurityUpdate
$update_id_list = @()
$update_id_list += $update_info.id

foreach($update_id in $update_id_list){
    Write-Output "Get file:"$update_id
    $kb_info_get = Get-MsrcCvrfDocument -ID $update_id -Verbose

    foreach($cve in $cve_list){
        Write-Output $cve
        $cve_info = $kb_info_get.Vulnerability | Where-Object CVE -match $cve
        $cve_description = $cve_info.Notes | Where-Object Type -match "2"
        Write-Output $cve_description.Value | % { $_ -replace $tag_delete, "" }
        $kb_info = $cve_info.Remediations | Where-Object Type -match "2"
        $kb_list = @()
        $kb_list += $kb_info.Description.Value
        $kb_list = $kb_list | Sort-Object | Get-Unique
        foreach($kb_number in $kb_list){
            $kb = "KB" + $kb_number
            Write-Output $kb
            $kb_production_id = $kb_info_get.Vulnerability.Remediations | Where-Object Description -match $kb_number
            Write-Output $kb_production_id.ProductID
        }
    }

    $production_info = $kb_info_get.ProductTree.FullProductName
    $production_id_list = @()
    $production_name_list = @()
    $production_id_list += $production_info.ProductID
    $production_name_list += $production_info.Value
    $i = 0
    foreach($production_id in $production_id_list){
        Write-Output $production_id
        Write-Output $production_name_list[$i]
        $i = $i + 1
    }
}
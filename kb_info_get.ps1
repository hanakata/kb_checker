Import-module msrcsecurityupdates
Set-MSRCApiKey -ApiKey "" -Verbose
# $update_info_list_dir = "C:\Users\mkatayama\Desktop\kb_info\"
# $update_info = Get-MsrcSecurityUpdate
# $update_id_list = @()
# $update_id_list += $update_info.id

# foreach($update_id in $update_id_list){
#     Write-Output "Get file:"$update_id
#     Get-MsrcCvrfDocument -ID $update_id -Verbose | 
#     Get-MsrcSecurityBulletinHtml -Verbose | 
#     Out-File $update_info_list_dir$update_id"_updatelist.html"
# }
$test = Get-MsrcCvrfDocument -ID 2017-Jan -Verbose
$test2 = $test.Vulnerability.Remediations | Where-Object Type -match "2" 
$kb_list = @()
$kb_list += $test2.Description.Value
$kb_list = $kb_list | Sort-Object | Get-Unique
foreach($kb_number in $kb_list){
    $kb = "KB" + $kb_number
    Write-Output $kb
    $kb_production_id = $test.Vulnerability.Remediations | Where-Object Description -match $kb_number
    Write-Output $kb_production_id.ProductID
}
$production_info = $test.ProductTree.FullProductName
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
Import-module msrcsecurityupdates
Set-MSRCApiKey -ApiKey "7bd197d2e8a34cacad9ba1c1361019ec" -Verbose
$update_info_list_dir = "C:\Users\mkatayama\Desktop\kb_info\"
$update_info = Get-MsrcSecurityUpdate
$update_id_list = @()
$update_id_list += $update_info.id

foreach($update_id in $update_id_list){
    Write-Output "Get file:"$update_id
    Get-MsrcCvrfDocument -ID $update_id -Verbose | 
    Get-MsrcSecurityBulletinHtml -Verbose | 
    Out-File $update_info_list_dir$update_id"_updatelist.html"
}
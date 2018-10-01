$filename = ".\check_list.txt"

$computer_list_all = Get-ADComputer -Filter * -Properties IPv4Address
foreach($computer_list in $computer_list_all){
    $computer_name = $computer_list.DNSHostName
    $computer_ip = $computer_list.IPv4Address
    $computer = $computer_name + "," + $computer_ip
    Write-Output $computer | Add-Content -Encoding utf8 $filename
}

$filename = ".\check_list.txt"
$computer_list_name = @()
$computer_list_ip = @()
$computer_list_all = Get-ADComputer -Filter * -Properties IPv4Address
foreach($computer_list in $computer_list_all){
    $computer_list_name += $computer_list.DNSHostName
    $computer_list_ip += $computer_list.IPv4Address
}

$i = 0

foreach($computer_name in $computer_list_name){
    $computer = $computer_name + "," + $computer_list_ip[$i]
    Write-Output $computer | Add-Content -Encoding utf8 $filename
    $i = $i + 1
}

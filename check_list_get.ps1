$filename = ".\check_list.txt"

$computer_list = Get-ADComputer -Filter *

Write-Output $computer_list.Name | Set-Content -Encoding utf8 $filename
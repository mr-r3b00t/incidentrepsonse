#$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
#$me
#$env:UserName
#$env:UserDomain

$myUsername = [System.Environment]::UserName
#[System.Environment]::DomainName


$users = Get-ADUser -Filter *
$users | ConvertTo-Json | Out-File "users.json"
$targets = $users | Select-Object -Property *|Where-Object {$_.SAMACCOUNTNAME -notin $myUsername}
foreach($user in $targets){
$user.SamAccountName
$user.DistinguishedName


$prefix = "Incident1!-"
$suffix = -join ((65..90) + (97..122) | Get-Random -Count 7 | % {[char]$_})
$randompassword = $prefix + $suffix.ToUpper()
$randompassword

#Set-ADAccountPassword -Identity $user.DistinguishedName -NewPassword (ConvertTo-SecureString -AsPlainText $randompassword -Force)

$output  = $user.SamAccountName + " " + $randompassword
$output | Out-File "Incident_reset_all_passwords.csv" -Append
}


if($users| Select-Object -Property SAMACCOUNTNAME|  Select-String -SimpleMatch -Pattern $myUsername){"found"}else{"Not Found"}
if($targets | Select-Object -Property SAMACCOUNTNAME|  Select-String -SimpleMatch -Pattern $myUsername){"found"}else{"Not Found"}

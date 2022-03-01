#Get-ADPrincipalGroupMembership nb | select name

$Efterligntextbox = "test"

$getusergroups = Get-ADUser –Identity $Efterligntextbox -Properties memberof | Select-Object -ExpandProperty memberof
#$getusergroups | Add-ADGroupMember -Members test -verbose
echo $getusergroups



Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Where-Object { $_.DistinguishedName -notlike '*OU=Domain Controllers,*' } | Format-Table Name, DistinguishedName -A

Get-ADObject -Filter { ObjectClass -eq 'organizationalunit' } -PropertiesCanonicalName | Select-Object -Property CanonicalName


$OU = 'OU=OU-Group,DC=odense,DC=local'

Get-ADOrganizationalUnit -SearchBase $OU -SearchScope Subtree -Filter * | 
     Select-Object DistinguishedName, Name

  
Get-ADOrganizationalUnit -SearchBase 'OU=OU-Group,DC=odense,DC=local' ` -SearchScope OneLevel -Filter * | Select-Object DistinguishedName, Name

	New-Item -path $PSScriptRoot -name settings.conf -type "file" -value "
[Domaininfo]
domainname=$dc1.$dc2
OUDC1=$dc1
OUDC2=$dc2
Homefolderip=$homefolder
"


$OU = Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object -Property Name, distinguishedname | Out-GridView -PassThru -Title "Select the OU"
$test = $OU.distinguishedname

$result = foreach($test in $OU){
    Get-BrokerMachine -MachineName $element | select LoadIndex -expand LoadIndex
}


$OU = Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object -Property Name | Out-GridView -PassThru -Title "Select the OU"
$count = 0
foreach ($OUunits in $OU.name)
{
  Write-Host $OUunits
  "dc$count=$OUunits" | Out-File -FilePath C:\settings.conf -Append -encoding ASCII
  $count++
}


Get-Content "C:\settings.conf" | foreach-object -begin { $h = @{ } } -process { $k = [regex]::split($_, '='); if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $h.Add($k[0], $k[1]) } }
$count = 0
foreach($item in $h){
    $h.Get_Item("OU").$count
    $count++
    }


    ForEach ($item in $) {
    Write-Host $Result.ObjectGUID $Result.ID
}



Get-Content "C:\settings.conf" | foreach-object -begin { $h = @{ } } -process { $k = [regex]::split($_, '='); if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $h.Add($k[0], $k[1]) } }

$h.Get_Item("OUnavn*")
for ($i=0; $i -lt $h.Length; $i++ )
{
    write-host "This is my $($h[$i])"
}


Get-Content "C:\settings.conf" | foreach-object -begin { $h = @{ } } -process { $k = [regex]::split($_, '='); if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $h.Add($k[0], $k[1]) } }

$h.Get_Item("OUnavn")
$IP = $h.Get_Item("OUnavn")

for ($i=0; $i -lt $IP.Length; $i++ )
{
    write-host "This is my $($IP[$i])"
}


$softwareList = Get-Content "C:\settings.conf" | foreach-object -begin { $h = @{ } } -process { $k = [regex]::split($_, '='); if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $h.Add($k[0], $k[1]) } }
$count = 0..($softwareList.count -1)
foreach($i in $count){
    Write-Host $softwareList.OUnavn[$i],$softwareList.OU[$i]
}


Get-Content "C:\settings.conf" | foreach-object -begin { $h = @{ } } -process { $k = [regex]::split($_, '='); if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $h.Add($k[0], $k[1]) } }

$m = $h.Get_Item("OUnavn0")
$m.Count





$ConfigFile = Get-Content "C:\settings.conf"

$ConfigFile | ForEach-Object -Begin {$settings=@{}} -Process {$store = [regex]::split($_,'='); if(($store[0].CompareTo("") -ne 0) -and ($store[0].StartsWith("[") -ne $True) -and ($store[0].StartsWith("#") -ne $True)) {$settings.Add($store[0], $store[1] -split ',')}}

$IPAddress = $settings.Get_Item("OU")
$Gateway = $settings.Get_Item("Gateway")
$PrimDNSServers = $settings.Get_Item("DNSServers")
$SecDNSServers = $settings.Get_Item("DNSServers") 




$ConfigFile = Get-Content "C:\Users\srvadm\Documents\SAPIEN\PowerShell Studio\Projects\adextra\settings.conf"
$ConfigFile | ForEach-Object -Begin {$settings=@{}} -Process {$store = [regex]::split($_,'='); if(($store[0].CompareTo("") -ne 0) -and ($store[0].StartsWith("[") -ne $True) -and ($store[0].StartsWith("#") -ne $True)) {$settings.Add($store[0], $store[1] -split ',')}}
$IPAddress = $settings.Get_Item("OUnavn") -split ','
$count = 0
foreach($item in $IPAddress){
echo ($settings.Get_Item("OUnavn") -split ',')[$count]
$count++
    }

    # Construct an out-array to use for data export
$OutArray = @()
$OU = Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object -Property Name, distinguishedname  | Out-GridView -PassThru -Title "Select the OU"

# The computer loop you already have
foreach ($OUunits in $ou)
    {
        # Construct an object
        $myobj = "" | Select "Name", "distinguishedname"

        # Fill the object
        $myobj.Name = $OU
        $myobj.distinguishedname = $OUunits

        # Add the object to the out-array
        $outarray += $myobj

        # Wipe the object just to be sure
        $myobj = $null
    }

# After the loop, export the array to CSV
$outarray | Out-File -FilePath c:\settings.conf



	$OU = Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object -Property Name, distinguishedname  | Out-GridView -PassThru -Title "Select the OU"
    Write-Host $OU.name
    $OU.name | Out-File -FilePath c:\settings.conf

	foreach ($OUunits in $OU)
	{
		Write-Host $OUunits.name
		Write-Host $OUunits.distinguishedname
		$ou1 = $OUunits.name
		$ou2 = $OUunits.distinguishedname
		#"OUnavn=$ou1" | Out-File -FilePath $PSScriptRoot\settings.conf -Append -encoding ASCII
		#"OU=$ou2" | Out-File -FilePath $PSScriptRoot\settings.conf -Append -encoding ASCII

	}



$groups = Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object -Property Name, distinguishedname  | Out-GridView -PassThru -Title "Select the OU"
$output = 
    Foreach($g in $groups)
    {
        write-output $g.Name 
        write-output "----------" 
    }
$output | Export-Csv -NoTypeInformation -Path C:\test3.txt -Append



$OUnavn = (Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty Name | Out-GridView -PassThru -Title "Select the OU") -join ","
"OUnavn=$OUnavn" | Out-File -FilePath c:\settings.conf -Append -encoding ASCII
$ou = (Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty distinguishedname | Out-GridView -PassThru -Title "Select the OU") -join ";"
"OUsti=$ou" | Out-File -FilePath c:\settings.conf -Append -encoding ASCII


$OUnavn = (Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty Name | Out-GridView -PassThru -Title "Select the OU") -join ";"

	foreach ($OUunits in $OUnavn)
	{
		Write-Host $OUunits
		echo $OUunits.distinguishedname

	}


$t = Get-ADOrganizationalUnit -Filter * | Select-Object -Property Name, distinguishedname | Out-GridView -PassThru -Title "Select the OU"
$t.name -join ','
$t.distinguishedname -join ';'

	$t = Get-ADOrganizationalUnit -Filter * | Select-Object -Property Name, distinguishedname | Out-GridView -PassThru -Title "Select the OU"
	"OUNavn="+$t.name -join ' ' | Out-File -FilePath $PSScriptRoot\settings.conf -Append -encoding ASCII
	"OUPath="+$t.distinguishedname -join ' ' | Out-File -FilePath $PSScriptRoot\settings.conf -Append -encoding ASCII
$Efterligntextbox = "nb"
#$brugernavn = "dan"
$getusergroups = (GET-ADUSER –Identity $Efterligntextbox –Properties MemberOf | Select-Object MemberOf).MemberOf
		#$getusergroups | Add-ADGroupMember -Members $brugernavn -verbose
		echo $getusergroups

$Efterligntextbox = "nb"
	if ($Efterligntextbox) { $getusergroups = Get-ADUser -Identity $Efterligntextbox -Properties memberof | Select-Object -ExpandProperty memberof
		#$getusergroups | Add-ADGroupMember -Members $brugernavn -verbose
		echo $getusergroups }
	else { 'empty' }


Get-ADPrincipalGroupMembership nb | select name


$str4 = ''
if ($str4) { 'not empty' } else { 'empty' }
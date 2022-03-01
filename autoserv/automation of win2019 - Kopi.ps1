Import-Module ActiveDirectory
import-module GroupPolicy
#---------------------------------------------------------------------------------------#
#  Requiroments
#  Need create a f drive
#  Delte Users from NTFS permissions (after running script)
#---------------------------------------------------------------------------------------#

#purpse of this script is to do active directory, HomeDrive, OU and Secourty groups with users added and created.
#home drive will be \\homeDrive\%username% on H

#variables
$dc="local" #domain.com or domain.local... 
$dcDomain = "Odense" #this is the domain it can be found under AD

#Store the data from ADUsers.csv in the $ADUsers variable
$ADUsers = Import-csv 'C:\Users\%USERPROFILE%\Desktop\AD users.csv'
$Password   = "Password1!"
#Loop through each row containing user details in the CSV file

#change the letter to which drive you wish to have the mapping made
$drive = "d"
#makes the directory
mkdir "$($drive):/administration"
mkdir "$($drive):/revision"
mkdir "$($drive):/everyone"
mkdir "$($drive):/HomeDrive"
mkdir "$($drive):/IT-admin/BG-img"
mkdir "$($drive):/IT-admin/files"
mkdir "$($drive):/Marketing"



#add a OU
#change the DC to the domain
#follow your AD anc change whats need (this will also create OU in the GPO)
New-ADOrganizationalUnit -Name "OU-Group" -Path "DC=$($dcDomain),DC=$($dc)"
New-ADOrganizationalUnit -Name "Administration" -Path "OU=OU-Group,DC=$($dcDomain),DC=$($dc)"
New-ADOrganizationalUnit -Name "Revision" -Path "OU=OU-Group,DC=$($dcDomain),DC=$($dc)"
New-ADOrganizationalUnit -Name "Marketing" -Path "OU=OU-Group,DC=$($dcDomain),DC=$($dc)"
New-ADOrganizationalUnit -Name "IT-admin" -Path "OU=OU-Group,DC=$($dcDomain),DC=$($dc)"


#adding SG Groups
New-ADGroup "SG-Administration" -Path "OU=Administration,OU=OU-Group,DC=$($dcDomain),DC=$($dc)" -GroupCategory Security -GroupScope Global -PassThru -Verbose
New-ADGroup "SG-Revision" -Path "OU=Revision,OU=OU-Group,DC=$($dcDomain),DC=$($dc)" -GroupCategory Security -GroupScope Global -PassThru -Verbose
New-ADGroup "SG-IT-Admin" -Path "OU=IT-admin,OU=OU-Group,DC=$($dcDomain),DC=$($dc)" -GroupCategory Security -GroupScope Global -PassThru -Verbose
New-ADGroup "SG-Marketing" -Path "OU=Marketing,OU=OU-Group,DC=$($dcDomain),DC=$($dc)" -GroupCategory Security -GroupScope Global -PassThru -Verbose

#creating a filter 
if ($ADUsers.Office -eq "Revision"){
    #Loop through each row containing user details in the CSV file
    foreach ($User in $ADUsers)
    {

        $Username = $User.SamAccountName
        $Firstname = $User.firstname
        $Lastname = $User.lastname
        $Office = $User.Office

           
            #Check to see if the user already exists in AD
            if (Get-ADUser -F {SamAccountName -eq $Username})
            {
                     #If user does exist, give a warning
                     Write-Warning "A user account with username $Username already exist in Active Directory."
            }
            elseif ($Office -eq "Revision" )
            {  
            #Account will be created in the OU provided by the $OU variable read from the CSV file
                 New-ADUser `
                -SamAccountName $Username `
                -UserPrincipalName "$Username@lm.local" `
                -Name "$Firstname $Lastname" `
                -GivenName $Firstname `
                -Surname $Lastname `
                -Office $Office `
                -Enabled $True `
                -DisplayName "$Lastname, $Firstname" `
                -Path "OU=Revision,OU=OU-Group,DC=$($dcDomain),DC=$($dc)" `
                -AccountPassword (convertto-securestring $Password -AsPlainText -Force)`
                -homedrive "H" `
                -homedirectory "\\$($dcDomain)\HomeDrive\$($Username)"

            }
            elseif ($Office -eq "IT-admin" )
            {
            #Account will be created in the OU provided by the $OU variable read from the CSV file
                 New-ADUser `
                -SamAccountName $Username `
                -UserPrincipalName "$Username@lm.local" `
                -Name "$Firstname $Lastname" `
                -GivenName $Firstname `
                -Surname $Lastname `
                -Office $Office `
                -Enabled $True `
                -DisplayName "$Lastname, $Firstname" `
                -Path "OU=IT-admin,OU=OU-Group,DC=$($dcDomain),DC=$($dc)" `
                -AccountPassword (convertto-securestring $Password -AsPlainText -Force)`
                -homedrive "H" `
                -homedirectory "\\$($dcDomain)\HomeDrive\$($Username)"

            }
            elseif ($Office -eq "Administration" )
            {              
            #Account will be created in the OU provided by the $OU variable read from the CSV file
                 New-ADUser `
                -SamAccountName $Username `
                -UserPrincipalName "$Username@lm.local" `
                -Name "$Firstname $Lastname" `
                -GivenName $Firstname `
                -Surname $Lastname `
                -Office $Office `
                -Enabled $True `
                -DisplayName "$Lastname, $Firstname" `
                -Path "OU=Administration,OU=OU-Group,DC=$($dcDomain),DC=$($dc)" `
                -AccountPassword (convertto-securestring $Password -AsPlainText -Force)`
                -homedrive "H" `
                -homedirectory "\\$($dcDomain)\HomeDrive\$($Username)"

            }
			elseif ($Office -eq "Marketing" )
            {              
            #Account will be created in the OU provided by the $OU variable read from the CSV file
                 New-ADUser `
                -SamAccountName $Username `
                -UserPrincipalName "$Username@lm.local" `
                -Name "$Firstname $Lastname" `
                -GivenName $Firstname `
                -Surname $Lastname `
                -Office $Office `
                -Enabled $True `
                -DisplayName "$Lastname, $Firstname" `
                -Path "OU=Marketing,OU=OU-Group,DC=$($dcDomain),DC=$($dc)" `
                -AccountPassword (convertto-securestring $Password -AsPlainText -Force)`
                -homedrive "H" `
                -homedirectory "\\$($dcDomain)\HomeDrive\$($Username)"

            }
        else
            {
            #if the OU are not made it will put them all in OU-Group
            #Account will be created in the OU provided by the $OU variable read from the CSV file
                 New-ADUser `
                -SamAccountName $Username `
                -UserPrincipalName "$Username@lm.local" `
                -Name "$Firstname $Lastname" `
                -GivenName $Firstname `
                -Surname $Lastname `
                -Office $Office `
                -Enabled $True `
                -DisplayName "$Lastname, $Firstname" `
                -Path "OU=OU-Group,DC=$($dcDomain),DC=$($dc)" `
                -AccountPassword (convertto-securestring $Password -AsPlainText -Force)`
                -homedrive "H" `
                -homedirectory "\\$($dcDomain)\HomeDrive\$($Username)"
                
            }
    }
}


#Sharing
New-SmbShare -Name "administration" -Path "$($drive):\administration" -FullAccess "SG-Administration"
New-SmbShare -Name "revision" -Path "$($drive):\revision" -FullAccess "SG-Revision"
New-SmbShare -Name "IT-admin" -Path "$($drive):\IT-admin" -FullAccess "SG-IT-admin"
New-SmbShare -Name "everyone" -Path "$($drive):\everyone" -FullAccess "SG-IT-admin" , "SG-Administration" , "SG-Revision"
New-SmbShare -Name "HomeDrive" -Path "$($drive):\HomeDrive" -FullAccess "Domain Users"
New-SmbShare -Name "BG-img" -Path "$($drive):\IT-admin\BG-img" -FullAccess "SG-IT-admin" 
New-SmbShare -Name "files" -Path "$($drive):\IT-admin\files" -FullAccess "SG-IT-admin"
New-SmbShare -Name "Marketing" -Path "$($drive):\Marketing" -FullAccess "SG-Marketing"


#NTFS permissions (security)

#everyone folder
$Acl = Get-Acl "$($drive):/everyone"
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SG-administration",
    "ReadAndExecute, ListDirectory",      # [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # [System.Security.AccessControl.InheritanceFlags]
    "None",      # [System.Security.AccessControl.PropagationFlags]
    "Allow"      # [System.Security.AccessControl.AccessControlType]
)))
(Get-Item "$($drive):/everyone").SetAccessControl($Acl)

$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SG-Revision",
    "ReadAndExecute, ListDirectory",      # [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # [System.Security.AccessControl.InheritanceFlags]
    "None",      # [System.Security.AccessControl.PropagationFlags]
    "Allow"      # [System.Security.AccessControl.AccessControlType]
)))
(Get-Item "$($drive):/everyone").SetAccessControl($Acl)

$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SG-IT-admin",
    "ReadAndExecute, ListDirectory",      # [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # [System.Security.AccessControl.InheritanceFlags]
    "None",      # [System.Security.AccessControl.PropagationFlags]
    "Allow"      # [System.Security.AccessControl.AccessControlType]
)))
(Get-Item "$($drive):/everyone").SetAccessControl($Acl)

#revision
$Acl = Get-Acl "$($drive):/revision"
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SG-revision",
    "ReadAndExecute, ListDirectory",      # [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # [System.Security.AccessControl.InheritanceFlags]
    "None",      # [System.Security.AccessControl.PropagationFlags]
    "Allow"      # [System.Security.AccessControl.AccessControlType]
)))
(Get-Item "$($drive):/revision").SetAccessControl($Acl)

#administration
$Acl = Get-Acl "$($drive):/administration"
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SG-administration",
    "ReadAndExecute, ListDirectory",      # [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # [System.Security.AccessControl.InheritanceFlags]
    "None",      # [System.Security.AccessControl.PropagationFlags]
    "Allow"      # [System.Security.AccessControl.AccessControlType]
)))
(Get-Item "$($drive):/administration").SetAccessControl($Acl)


#IT-admin
$Acl = Get-Acl "$($drive):/IT-admin"
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SG-IT-admin",
    "ReadAndExecute, ListDirectory",      # [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # [System.Security.AccessControl.InheritanceFlags]
    "None",      # [System.Security.AccessControl.PropagationFlags]
    "Allow"      # [System.Security.AccessControl.AccessControlType]
)))
(Get-Item "$($drive):/IT-admin").SetAccessControl($Acl)

#Marketing
$Acl = Get-Acl "$($drive):/Marketing"
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SG-Marketing",
    "ReadAndExecute, ListDirectory",      # [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # [System.Security.AccessControl.InheritanceFlags]
    "None",      # [System.Security.AccessControl.PropagationFlags]
    "Allow"      # [System.Security.AccessControl.AccessControlType]
)))
(Get-Item "$($drive):/Marketing").SetAccessControl($Acl)


#this is commed out bc there is a better way as seen above
#grant access to sharing (I do this when we create the file to begin with but if its missing)
#Grant-SmbShareAccess -Name "administration" -AccountName "SG-Administration" -AccessRight Full -Force
#Grant-SmbShareAccess -Name "revision" -AccountName "SG-revision" -AccessRight Full -Force
#Grant-SmbShareAccess -Name "IT-admin" -AccountName "SG-IT-admin" -AccessRight Full -Force
#Grant-SmbShareAccess -Name "background-img" -AccountName "SG-IT-admin" -AccessRight Full -Force
#Grant-SmbShareAccess -Name "files" -AccountName "SG-IT-admin" -AccessRight Full -Force
#Grant-SmbShareAccess -Name "everyone" -AccountName "SG-IT-admin","SG-revision","SG-Administration" -AccessRight Full -Force

#this is commed out because this the above code removes it automatic and this might come in handi some day
#remove everyone from the shared file (this is not need since everyone role does not get added when creating it (but if need keep it))

#Revoke-SmbShareAccess -Name administration -AccountName Everyone -Force
#Revoke-SmbShareAccess -Name revision -AccountName Everyone -Force
#Revoke-SmbShareAccess -Name IT-admin -AccountName Everyone -Force
#Revoke-SmbShareAccess -Name background-img -AccountName Everyone -Force
#Revoke-SmbShareAccess -Name files -AccountName Everyone -Force
#Revoke-SmbShareAccess -Name everyone -AccountName Everyone -Force


#GPO - only very few thigns can be done in powershell to create gpos and that is using regierstry keys (Set-GPRegistryValue)
#New-GPO -Name "GPO-HomeDrive" -Comment "home drive" | New-GPLink -Target "OU=OU-Group,DC=$($dcDomain),DC=$($dc)" -LinkEnabled Yes | Set-GPPermission -All -TargetName "SG-IT-admin", "SG-revision" , "SG-administration" -PermissionLevel GpoEdit -Replace
#this wont work but ill leave it here just in case
#New-GPO -Name "GPO-HomeDrive" -Comment "home drive to all users" |  | Set-GPPermission -Replace -PermissionLevel None -TargetName "Authenticated Users" -TargetType Group | Set-GPPermission -PermissionLevel GpoApply -TargetName "SG-IT-admin", "SG-revision" , "SG-administration" -TargetType Group | New-GPLink -Target "OU=OU-Group,DC=$($dcDomain),DC=$($dc)" -LinkEnabled Yes -Enforced Yes

#################################################################################
#Powershell and GPO - the things you can do
#################################################################################

#Creating/Deleting/Renaming/Getting GPOs
#Backup/Restore/Copy/Import GPOs
#Creating/Getting Starter GPOs
#Getting/Setting GP Inheritance
#Getting/Setting GPO Permissions
#Creating/Deleting/Modifying GPO Links
#Get GPO Settings and RSoP Reports
#Getting/Setting/Deleting Administrative Template Settings
#Getting/Setting/Deleting GP Preferences Registry Policy

#################################################################################

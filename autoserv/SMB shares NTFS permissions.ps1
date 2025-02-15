﻿mkdir "$($drive):/revision"
mkdir "$($drive):/everyone"
mkdir "$($drive):/HomeDrive"
mkdir "$($drive):/IT-admin/BG-img"
mkdir "$($drive):/IT-admin/files"
mkdir "$($drive):/Marketing"

#Sharing
#New-SmbShare -Name "administration" -Path "$($drive):\administration" -FullAccess "SG-Administration"
New-SmbShare -Name "revision" -Path "$($drive):\revision" -FullAccess "SG-Revision"
New-SmbShare -Name "IT-admin" -Path "$($drive):\IT-admin" -FullAccess "SG-IT-admin"
New-SmbShare -Name "everyone" -Path "$($drive):\everyone" -FullAccess "SG-IT-admin" , "SG-Administration" , "SG-Revision"
New-SmbShare -Name "HomeDrive" -Path "$($drive):\HomeDrive" -FullAccess "Domain Users"
New-SmbShare -Name "BG-img" -Path "$($drive):\IT-admin\BG-img" -FullAccess "SG-IT-admin" 
New-SmbShare -Name "files" -Path "$($drive):\IT-admin\files" -FullAccess "SG-IT-admin"
New-SmbShare -Name "Marketing" -Path "$($drive):\Marketing" -FullAccess "SG-Marketing"



#everyone folder
#$Acl = Get-Acl "$($drive):/everyone"
#$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
#    "SG-administration",
#    "ReadAndExecute, ListDirectory",      # [System.Security.AccessControl.FileSystemRights]
#    "ContainerInherit, ObjectInherit", # [System.Security.AccessControl.InheritanceFlags]
#    "None",      # [System.Security.AccessControl.PropagationFlags]
#    "Allow"      # [System.Security.AccessControl.AccessControlType]
#)))
#(Get-Item "$($drive):/everyone").SetAccessControl($Acl)

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
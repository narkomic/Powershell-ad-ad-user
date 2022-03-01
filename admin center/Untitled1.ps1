param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

'running with full privileges'



## Download the msi file
Invoke-WebRequest 'https://aka.ms/WACDownload' -OutFile "$pwd\WAC.msi"

## install windows admin center
$msiArgs = @("/i", "$pwd\WAC.msi", "/qn", "/L*v", "log.txt", "SME_PORT=6516", "SSL_CERTIFICATE_OPTION=generate")
Start-Process msiexec.exe -Wait -ArgumentList $msiArgs
# /qn betyder q= quiet  n = Ingen brugergrænseflade
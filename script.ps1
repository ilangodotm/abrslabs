function configTimeZone {
    $metadataUrl = "http://169.254.169.254/metadata/instance?api-version=2020-06-01"
    $metadataHeaders = @{Metadata="true"}

    $location = Invoke-RestMethod -Uri $metadataUrl -Headers $metadataHeaders | Select-Object -ExpandProperty compute | Select-Object -ExpandProperty location

    Write-Host "VM location/region: $location"

$region=$location
# Define a mapping table between Azure regions and timezones
$regionTimezoneMap = @{
    "australiacentral" = "AUS Central Standard Time"
    "australiacentral2" = "AUS Central Standard Time"
    "australiaeast" = "AUS Eastern Standard Time"
    "australiasoutheast" = "AUS Eastern Standard Time"
    "brazilsouth" = "E. South America Standard Time"
    "canadacentral" = "Canada Central Standard Time"
    "canadaeast" = "Eastern Standard Time"
    "centralindia" = "India Standard Time"
    "centralus" = "Central Standard Time"
    "eastasia" = "Tokyo Standard Time"
    "eastus" = "Eastern Standard Time"
    "eastus2" = "Eastern Standard Time"
    "francecentral" = "Romance Standard Time"
    "germanywestcentral" = "W. Europe Standard Time"
    "japaneast" = "Tokyo Standard Time"
    "koreacentral" = "Korea Standard Time"
    "northeurope" = "W. Europe Standard Time"
    "southafricanorth" = "South Africa Standard Time"
    "southcentralus" = "Central Standard Time"
    "southeastasia" = "Singapore Standard Time"
    "southindia" = "India Standard Time"
    "uksouth" = "GMT Standard Time"
    "ukwest" = "GMT Standard Time"
    "westcentralus" = "Central Standard Time"
    "westeurope" = "W. Europe Standard Time"
    "westindia" = "India Standard Time"
    "westus" = "Pacific Standard Time"
    "westus2" = "Pacific Standard Time"
}


# Set the timezone based on the Azure region
if ($regionTimezoneMap.ContainsKey($region.ToLower())) {
    $timezone = $regionTimezoneMap[$region.ToLower()]
    Write-Host "Setting timezone to $timezone"
    Set-TimeZone -Id $timezone
} else {
    Write-Host "No timezone mapping found for region $region"
}

}

function installEdgeBrowser {
	Invoke-WebRequest "https://go.microsoft.com/fwlink/?linkid=2069324" -OutFile MicrosoftEdgeEnterpriseX64.msi
	Start-Process msiexec.exe -Wait -ArgumentList '/i MicrosoftEdgeEnterpriseX64.msi /qn /norestart /l*v log.txt'
}


#Call function to set timezone based on VM location
configTimeZone

#Call function to install Edge browser
installEdgeBrowser


#disable IE ESC
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0

#Open ports 5985 & 5986 on the host machine for powershell remote session
Enable-PSRemoting -Force -Verbose
New-NetFirewallRule -DisplayName 'WinRM Inbound' -Profile @('Domain', 'Private') -Direction Inbound -Action Allow -Protocol TCP -LocalPort @('5985', '5986')

# Extend the C: volume to the end i.e. from default ~127 GB size to match with the 512 OS disk size for HyperV host
Resize-Partition -DriveLetter C -Size (Get-PartitionSupportedSize -DriveLetter C).SizeMax

#Install Hyper-V manager tools
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
Install-WindowsFeature RSAT-Hyper-V-Tools -IncludeAllSubFeature

#Install DHCP role to provide IP addresses automatically for Guest VMS
# Install DHCP Server role
Install-WindowsFeature -Name DHCP -IncludeManagementTools -Restart:$false



#Preparing for startup-script on next boot.
mkdir "C:\Path\To\MyScript\"

$ScriptName = "C:\Path\To\MyScript\startup-script.ps1"
@'
#startup-script on next boot.

#Connecting to VM templates file share
$connectTestResult = Test-NetConnection -ComputerName blobbackupstore01.file.core.windows.net -Port 445
if ($connectTestResult.TcpTestSucceeded) {
    # Save the password so the drive will persist on reboot
    cmd.exe /C "cmdkey /add:`"blobbackupstore01.file.core.windows.net`" /user:`"localhost\blobbackupstore01`" /pass:`"ERwQkPa5CE8cXDmv5Z4KYuTsRut88tnjQKRcuxK2lk5fFfjn3d6LlaNxI8e1teAEgwlbAue9PlvK+AStOP7ijg==`""
    # Mount the drive
    New-PSDrive -Name Z -PSProvider FileSystem -Root "\\blobbackupstore01.file.core.windows.net\hyperv-vm-templates" -Persist
} else {
    Write-Error -Message "Unable to reach the Azure storage account via port 445. Check to make sure your organization or ISP is not blocking port 445, or use Azure P2S VPN, Azure S2S VPN, or Express Route to tunnel SMB traffic over a different port."
}


#Create an Internal switch
New-VMSwitch -Name "InternalNATSwitch" -SwitchType Internal
$InternatNATAdapter = Get-NetAdapter | Where-Object {$_.Name -like "*InternalNATSwitch*"}
New-NetIPAddress -IpAddress 192.168.0.1 -PrefixLength 24 -InterfaceIndex $InternatNATAdapter.ifIndex
New-NetNat -Name "InternalNATSwitch" -InternalIPInterfaceAddressPrefix 192.168.0.0/24

# Configure DHCP scope settings
$Scope = "192.168.0.0/24"
$SubnetMask = "255.255.255.0"
$StartRange = "192.168.0.4"
$EndRange = "192.168.0.254"
$Gateway = "192.168.0.1"
$DNSServer = "168.63.129.16"
Add-DhcpServerv4Scope -Name "MyScope" -StartRange $StartRange -EndRange $EndRange -SubnetMask $SubnetMask -State Active

# Configure DHCP options for default gateway and DNS server
Set-DhcpServerv4OptionValue -OptionId 3 -Value $Gateway
Set-DhcpServerv4OptionValue -OptionId 6 -Value $DNSServer

#VM create samples
#New-VM -Name VM01 -MemoryStartupBytes 2147483648 -Generation 1 -NewVHDPath 'C:\Virtual Machines\VM01\VM01.vhdx' -NewVHDSizeBytes 53687091200 -BootDevice VHD -Path 'C:\Virtual Machines\VM01' -SwitchName (Get-VMSwitch).Name
#New-VM -Name Win10VM -MemoryStartupBytes 4GB -BootDevice VHD -VHDPath .\VMs\Win10.vhdx -Path .\VMData -Generation 2 -Switch ExternalSwitch

#Configure VMs
#download the prepared VHDX template
#$url = "https://blobbackupstore01.blob.core.windows.net/scripts/Win2016G1.vhdx"
#Invoke-WebRequest -Uri $url -OutFile "$outputPath"

####################VM creation steps start

New-Item -ItemType directory -Path  "C:\VMTemplates\"
#download the prepared VHDX template
#$url = "https://blobbackupstore01.blob.core.windows.net/scripts/Win2016G1.vhdx"
Copy-Item -Path "Z:\HyperV-VM-Templates\*" -Destination "C:\VMTemplates\" -Recurse
New-Item -ItemType directory -Path "C:\Virtual Machines\"

$VMTemplateVHDPath = "C:\VMTemplates\Win2016G1.vhdx"
$VMNotes = "Windows 2016 Generation1 VM"
$VMName = "CS01"
$VHDPath = "C:\Virtual Machines\$VMName\$VMName.vhdx"
$VMPath = "C:\Virtual Machines\$VMName\"
New-Item -ItemType directory -Path "$VMPath"
Copy-Item -Path "$VMTemplateVHDPath" -Destination "$VHDPath"
New-VM -Name $VMName -MemoryStartupBytes 8GB -BootDevice VHD -VHDPath "$VHDPath" -Path "$VMPath" -Generation 1 -Switch InternalNATSwitch
Set-VM "$VMName" -ProcessorCount 2 -DynamicMemory -MemoryStartupBytes 4GB -MemoryMinimumBytes 2GB -MemoryMaximumBytes 8GB  -Notes "$VMNotes"
Start-Sleep -Seconds 5
Start-VM -Name "$VMName"

$VMTemplateVHDPath = "C:\VMTemplates\Win2016G2.vhdx"
$VMNotes = "Windows 2016 Generation2 VM"
$VMName = "PS01"
$VHDPath = "C:\Virtual Machines\$VMName\$VMName.vhdx"
$VMPath = "C:\Virtual Machines\$VMName\"
New-Item -ItemType directory -Path "$VMPath"
Copy-Item -Path "$VMTemplateVHDPath" -Destination "$VHDPath"
New-VM -Name $VMName -MemoryStartupBytes 8GB -BootDevice VHD -VHDPath "$VHDPath" -Path "$VMPath" -Generation 2 -Switch InternalNATSwitch
Set-VMFirmware "$VMName" -EnableSecureBoot Off
Set-VM "$VMName" -ProcessorCount 2 -DynamicMemory -MemoryStartupBytes 4GB -MemoryMinimumBytes 2GB -MemoryMaximumBytes 8GB -Notes "$VMNotes"
Start-Sleep -Seconds 5
Start-VM -Name "$VMName"

$VMTemplateVHDPath = "C:\VMTemplates\CentOS79G1.vhdx"
$VMNotes = "Linux CentOS 7.9 Generation1 VM"
$VMName = "Lin01"
$VHDPath = "C:\Virtual Machines\$VMName\$VMName.vhdx"
$VMPath = "C:\Virtual Machines\$VMName\"
New-Item -ItemType directory -Path "$VMPath"
Copy-Item -Path "$VMTemplateVHDPath" -Destination "$VHDPath"
New-VM -Name $VMName -MemoryStartupBytes 4GB -BootDevice VHD -VHDPath "$VHDPath" -Path "$VMPath" -Generation 1 -Switch InternalNATSwitch
Set-VM "$VMName" -ProcessorCount 1 -DynamicMemory -MemoryStartupBytes 2GB -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB -Notes "$VMNotes"
Start-Sleep -Seconds 5
Start-VM -Name "$VMName"

$VMTemplateVHDPath = "C:\VMTemplates\CentOS79G2.vhdx"
$VMNotes = "Linux CentOS 7.9 Generation2 VM"
$VMName = "Lin02"
$VHDPath = "C:\Virtual Machines\$VMName\$VMName.vhdx"
$VMPath = "C:\Virtual Machines\$VMName\"
New-Item -ItemType directory -Path "$VMPath"
Copy-Item -Path "$VMTemplateVHDPath" -Destination "$VHDPath"
New-VM -Name $VMName -MemoryStartupBytes 4GB -BootDevice VHD -VHDPath "$VHDPath" -Path "$VMPath" -Generation 2 -Switch InternalNATSwitch
Set-VMFirmware "$VMName" -EnableSecureBoot Off
Set-VM "$VMName" -ProcessorCount 1 -DynamicMemory -MemoryStartupBytes 2GB -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB -Notes "$VMNotes"
Start-Sleep -Seconds 5
Start-VM -Name "$VMName"

####################VM creation steps End

#Disabling the schedule task after execution
Disable-ScheduledTask -TaskName "ConfigureExternalSwitchAndVMs"
'@ | Out-File -FilePath $ScriptName 



# Create a scheduled task to run the script at startup
$TaskName = "ConfigureExternalSwitchAndVMs"
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -Command `"$ScriptName`""
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup

Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -User "SYSTEM" -RunLevel Highest -Force

#Restart computer after installing Hyper-V and setting the startup script.
Restart-Computer
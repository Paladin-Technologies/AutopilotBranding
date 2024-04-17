Set-ExecutionPolicy -ExecutionPolicy Bypass

Import-Module -Name ".\ImportRegistryHive.psm1"

Function Log(){
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$false)] [String] $Message
	)

	$Timestamp = Get-Date -f "yyyy/MM/dd hh:mm:ss tt"
	Write-Output "$Timestamp $Message"
}





# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
If("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64"){
    If(Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe"){
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -File "$PSCommandPath"
        Exit $lastexitcode
    }
}


# Start logging
Start-Transcript "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"


# PREP: Load the Config.xml
$InstallFolder = "$PSScriptRoot\"
Log "Install folder: $InstallFolder"
Log "Loading configuration: $($InstallFolder)Config.xml"
[Xml]$Config = Get-Content -Path "$($InstallFolder)Config.xml"


# STEP 1: Apply custom start menu layout
$CompInfo = Get-ComputerInfo
If($CompInfo.OsBuildNumber -le 22000) {
	Log "Importing layout: $($InstallFolder)Layout.xml"
	Copy-Item -Path "$($InstallFolder)Layout.xml" -Destination "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Force
}Else{
	Log "Importing layout: $($InstallFolder)Start2.bin"
	MkDir -Path "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item -Path "$($InstallFolder)Start2.bin" -Destination "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin" -Force
}


# STEP 2: Configure background
Log "Setting up Autopilot theme"
$ThemesFolder = Join-Path -Path $Env:windir -ChildPath "Resources\OEM Themes"
If(-not (Test-Path -Path $ThemesFolder)){ New-Item -Path $ThemesFolder -Type Directory -Force }
Copy-Item -Path ".\Paladin.theme" -Destination $ThemesFolder -Force

$WallpaperFolder = Join-Path -Path $Env:windir -ChildPath "Web\Wallpaper\Paladin"
If(-not (Test-Path -Path $WallpaperFolder)){ New-Item -Path $WallpaperFolder -Type Directory -Force }
Copy-Item -Path ".\Wallpaper_Vehicle_1.png" -Destination $WallpaperFolder -Force

# Load the NTUSER.DAT into HKLM\TEMP_HIVE, this can be accessed using the PSDrive TempHive
Import-RegistryHive -File "C:\Users\Default\NTUSER.DAT" -Key "HKLM\TEMP_HIVE" -Name "TempHive"


Log "Setting Autopilot theme as the new user default"
# Using TempHive we make changes to turn on "boot to desktop" in the Default profile

# Set the default theme to the Paladin theme
New-Item -Path 'TempHive:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Force
New-ItemProperty -Path 'TempHive:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Name 'InstallTheme' -Value (Join-Path -Path $ThemesFolder -ChildPath "Paladin.theme") -PropertyType 'ExpandString'

New-Item -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Force
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'AuthCheckSelect' -Value 1 -Force	# Show checkboxes
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0 -Force		# Show all file extensions
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarAl' -Value 0 -Force		# Align the taskbar to the left
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'UseCompactMode' -Value 1 -Force	# Use the compact view in Explorer


#reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Host
#reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v InstallTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\Autopilot.theme" /f | Out-Host
#reg.exe unload HKLM\TempUser | Out-Host

# Remove TempHive and unload the registry hive HKLM\TEMP_HIVE
Remove-RegistryHive -Name "TempHive"


# Copy default user profile pictures
Remove-Item -Path "$Env:ProgramData\Microsoft\User Account Pictures\*.bmp" -Force
Remove-Item -Path "$Env:ProgramData\Microsoft\User Account Pictures\*.png" -Force
Copy-Item -Path ".\DefaultProfilePics\*.bmp" -Destination "$Env:ProgramData\Microsoft\User Account Pictures" -Force
Copy-Item -Path ".\DefaultProfilePics\*.png" -Destination "$Env:ProgramData\Microsoft\User Account Pictures" -Force



# STEP 3: Set time zone (if specified)
If($Config.Config.TimeZone) {
	Log "Setting time zone: $($Config.Config.TimeZone)"
	Set-Timezone -Id $Config.Config.TimeZone
}Else{
	Log "Enabling automatic timezone"
	# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
	Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
}


# STEP 4: Remove specified provisioned apps if they exist
Log "Removing specified in-box provisioned apps"
$apps = Get-AppxProvisionedPackage -online
$Config.Config.RemoveApps.App | % {
	$current = $_
	$apps | ? {$_.DisplayName -eq $current} | % {
		try {
			Log "Removing provisioned app: $current"
			$_ | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
		} catch { }
	}
}


# STEP 5: Install OneDrive per machine
If($Config.Config.OneDriveSetup) {
	Log "Downloading OneDriveSetup"
	$dest = "$($env:TEMP)\OneDriveSetup.exe"
	$client = new-object System.Net.WebClient
	$client.DownloadFile($Config.Config.OneDriveSetup, $dest)
	Log "Installing: $dest"
	$proc = Start-Process $dest -ArgumentList "/allusers" -WindowStyle Hidden -PassThru
	$proc.WaitForExit()
	Log "OneDriveSetup exit code: $($proc.ExitCode)"
}


# STEP 6: Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
Log "Turning off (old) Edge desktop shortcut"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'DisableEdgeDesktopShortcutCreation' -Value 1 -Force	# Prevent Edge from making a desktop shortcut
# STEP 15: Disable new Edge desktop icon
Log "Turning off Edge desktop icon"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name 'CreateDesktopShortcutDefault' -Value 0 -Force	# Prevent Edge from making a desktop shortcut



# STEP 7: Add language packs
Get-ChildItem "$($InstallFolder)LPs" -Filter *.cab | % {
	Log "Adding language pack: $($_.FullName)"
	Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName
}


# STEP 8: Change language
If($Config.Config.Language) {
	Log "Configuring language using: $($Config.Config.Language)"
	& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$($InstallFolder)$($Config.Config.Language)`""
}


# STEP 9: Add features on demand
$currentWU = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
If($currentWU -eq 1){
	Log "Turning off WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 0
	Restart-Service wuauserv
}
If($Config.Config.AddFeatures.Feature.Count -gt 0){
	$Config.Config.AddFeatures.Feature | % {
		Log "Adding Windows feature: $_"
		Add-WindowsCapability -Online -Name $_ -ErrorAction SilentlyContinue | Out-Null
	}
}
If($currentWU -eq 1){
	Log "Turning on WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 1
	Restart-Service wuauserv
}


# STEP 10: Customize default apps
# Export default app associations: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/export-or-import-default-application-associations?view=windows-11
If($Config.Config.DefaultApps) {
	Log "Setting default apps: $($Config.Config.DefaultApps)"
	& Dism.exe /Online /Import-DefaultAppAssociations:`"$($InstallFolder)$($Config.Config.DefaultApps)`"
}


# STEP 11: Set registered user and organization
If($Config.Config.RegisteredOwner){
	Log "Configuring registered user information"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "$($Config.Config.RegisteredOwner)" /f /reg:64 | Out-Host
}
If($Config.Config.RegisteredOrganization){
	Log "Configuring registered organization information"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "$($Config.Config.RegisteredOrganization)" /f /reg:64 | Out-Host
}


# STEP 12: Configure OEM branding info
If($Config.Config.OEMInfo){
	Log "Configuring OEM branding info"

	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /t REG_SZ /d "$($Config.Config.OEMInfo.Manufacturer)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /t REG_SZ /d "$($Config.Config.OEMInfo.Model)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /t REG_SZ /d "$($Config.Config.OEMInfo.SupportPhone)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /t REG_SZ /d "$($Config.Config.OEMInfo.SupportHours)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /t REG_SZ /d "$($Config.Config.OEMInfo.SupportURL)" /f /reg:64 | Out-Host
	Copy-Item "$InstallFolder\$($Config.Config.OEMInfo.Logo)" "C:\Windows\$($Config.Config.OEMInfo.Logo)" -Force
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "C:\Windows\$($Config.Config.OEMInfo.Logo)" /f /reg:64 | Out-Host
}


# STEP 13: Enable UE-V
Log "Enabling UE-V"
Enable-Uev
Set-UevConfiguration -Computer -SettingsStoragePath "%OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
Get-ChildItem "$($InstallFolder)UEV" -Filter *.xml | % {
	Log "Registering template: $($_.FullName)"
	Register-UevTemplate -Path $_.FullName
}


# STEP 14: Disable network location fly-out
Log "Turning off network location fly-out"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f


# Create a tag file just so Intune knows this was installed
If(-not (Test-Path "$($env:ProgramData)\Microsoft\AutopilotBranding")){
    #Mkdir "$($env:ProgramData)\Microsoft\AutopilotBranding"
	New-Item -Path "$($env:ProgramData)\Microsoft\AutopilotBranding" -Type Directory -Force
}
Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

Write-Output -InputObject "Success"

Stop-Transcript

Set-ExecutionPolicy -ExecutionPolicy Bypass

Import-Module -Name ".\ImportRegistryHive.psm1"

Function Add-Log(){
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$false)] [String] $Message
	)

	$Timestamp = Get-Date -f "yyyy/MM/dd hh:mm:ss tt"
	Write-Output "$Timestamp: $Message"
}

$InstallFolder = $PSScriptRoot



# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
If("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64"){
    If(Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe"){
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -File "$PSCommandPath"
        Exit $lastexitcode
    }
}


# Start logging
Start-Transcript "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"

Add-Log -Message "Starting script"
Add-Log -Message "Working from $InstallFolder"


# PREP: Load the Config.xml
$ConfigFile = Join-Path -Path $InstallFolder -ChildPath "Config.xml"
Add-Log -Message "Loading configuration: $ConfigFile"
[Xml]$Config = Get-Content -Path $ConfigFile


# STEP 1: Apply custom start menu layout
$CompInfo = Get-ComputerInfo
If($CompInfo.OsBuildNumber -le 22000){
	Add-Log -Message "Importing layout: $($InstallFolder)Layout.xml"
	Copy-Item -Path ".\Layout.xml" -Destination "$($Env:SystemDrive)\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Force
}Else{
	Add-Log -Message "Importing layout: $($InstallFolder)Start2.bin"
	#MkDir -Path "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force -ErrorAction SilentlyContinue | Out-Null
	If(-not (Test-Path -Path "$($Env:SystemDrive)\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState")){
		New-Item -Path "$($Env:SystemDrive)\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Type Directory -Force
	}
	Copy-Item -Path ".\Start2.bin" -Destination "$($Env:SystemDrive)\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin" -Force
}


# STEP 2: Configure background
Add-Log -Message "Adding Paladin theme to OEM theme folder"
$ThemesFolder = Join-Path -Path $Env:windir -ChildPath "Resources\OEM Themes"
If(-not (Test-Path -Path $ThemesFolder)){
	Add-Log -Message "OEM theme folder does not exist, creating"
	New-Item -Path $ThemesFolder -Type Directory -Force
}
Copy-Item -Path ".\Paladin.theme" -Destination $ThemesFolder -Force


Add-Log -Message "Adding Paladin wallpaper to Paladin wallpaper folder"
$WallpaperFolder = Join-Path -Path $Env:windir -ChildPath "Web\Wallpaper\Paladin"
If(-not (Test-Path -Path $WallpaperFolder)){
	Add-Log -Message "Paladin wallpaper folder does not exist, creating"
	New-Item -Path $WallpaperFolder -Type Directory -Force
}
Copy-Item -Path ".\Wallpaper_Vehicle_1.png" -Destination $WallpaperFolder -Force


Add-Log -Message "Setting default lock screen image"
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\Personalization' -Force
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Personalization' -Name 'LockScreenImage' -Value (Join-Path -Path $WallpaperFolder -ChildPath "Wallpaper_Vehicle_1.png") -PropertyType 'String' -Force


# Load the NTUSER.DAT into HKLM\TEMP_HIVE, this can be accessed using the PSDrive TempHive
$HiveFile = Join-Path -Path $Env:SystemDrive -ChildPath "Users\Default\NTUSER.DAT"
Add-Log -Message "Loading default user hive: $HiveFile"
Import-RegistryHive -File $HiveFile -Key "HKLM\TEMP_HIVE" -Name "TempHive"


# Set the default theme to the Paladin theme
Add-Log -Message "Setting Paladin theme as the new user default"
New-Item -Path 'TempHive:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Force
New-ItemProperty -Path 'TempHive:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Name 'InstallTheme' -Value (Join-Path -Path $ThemesFolder -ChildPath "Paladin.theme") -PropertyType 'ExpandString'

Add-Log -Message "Adding default user experience options"
New-Item -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Force
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowFrequent' -Value 0 -Force	# Don't show frequent folders
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'AuthCheckSelect' -Value 1 -Force	# Show checkboxes
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0 -Force		# Show all file extensions
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarAl' -Value 0 -Force		# Align the taskbar to the left
New-ItemProperty -Path 'TempHive:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'UseCompactMode' -Value 1 -Force	# Use the compact view in Explorer


# Remove TempHive and unload the registry hive HKLM\TEMP_HIVE
Add-Log -Message "Closing default user hive"

# Found here: https://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html
# attempt Remove-RegistryHive a maximum of 3 times
$attempt = 0
while($true)
{
    try
    {
        # when Remove-RegistryHive is successful break will stop the loop
        $attempt++
        Remove-RegistryHive -Name TempHive
        Add-Log -Message 'NTUSER.DAT updated successfully!'
        break
    }
    catch
    {
        if ($attempt -eq 3)
        {
            # rethrow the exception, we gave up
            throw
        }

        Add-Log -Message 'Remove-RegistryHive failed, trying again...'

        # wait for 100ms and trigger the garbage collector
        Start-Sleep -Milliseconds 100
        [gc]::Collect()
    }
}


# Copy default user profile pictures
Add-Log -Message "Changing default user photos"
Remove-Item -Path "$Env:ProgramData\Microsoft\User Account Pictures\*.bmp" -Force
Remove-Item -Path "$Env:ProgramData\Microsoft\User Account Pictures\*.png" -Force
Copy-Item -Path ".\DefaultProfilePics\*.bmp" -Destination "$Env:ProgramData\Microsoft\User Account Pictures" -Force
Copy-Item -Path ".\DefaultProfilePics\*.png" -Destination "$Env:ProgramData\Microsoft\User Account Pictures" -Force



# STEP 3: Set time zone (if specified)
If($Config.Config.TimeZone) {
	Add-Log -Message "Setting time zone: $($Config.Config.TimeZone)"
	Set-Timezone -Id $Config.Config.TimeZone
}Else{
	Add-Log -Message "Enabling automatic timezone"
	# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
	Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
}


# STEP 4: Remove specified provisioned apps if they exist
Add-Log -Message "Removing specified in-box provisioned apps"
$Apps = Get-AppxProvisionedPackage -Online
$Config.Config.RemoveApps.App | ForEach-Object {
	$AppToRemove = $_ # App from configuration
	$Apps | Where-Object {$_.DisplayName -eq $AppToRemove} | ForEach-Object {
		try {
			Add-Log -Message "Removing provisioned app: $AppToRemove"
			$_ | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
		} catch { }
	}
}


# STEP 5: Install OneDrive per machine
If($Config.Config.OneDriveSetup) {
	Add-Log -Message "Downloading OneDriveSetup"
	$Dest = "$($Env:TEMP)\OneDriveSetup.exe"
	$Client = New-Object System.Net.WebClient
	$Client.DownloadFile($Config.Config.OneDriveSetup, $Dest)
	
	Add-Log -Message "Installing: $dest"
	$Proc = Start-Process $Dest -ArgumentList "/allusers" -WindowStyle Hidden -PassThru
	$Proc.WaitForExit()
	Add-Log -Message "OneDriveSetup exit code: $($Proc.ExitCode)"
}


# STEP 6: Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
Add-Log -Message "Turning off (old) Edge desktop shortcut"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'DisableEdgeDesktopShortcutCreation' -Value 1 -Force	# Prevent Edge from making a desktop shortcut
# STEP 15: Disable new Edge desktop icon
Add-Log -Message "Turning off Edge desktop icon"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name 'CreateDesktopShortcutDefault' -Value 0 -Force	# Prevent Edge from making a desktop shortcut



# STEP 7: Add language packs
Get-ChildItem "$($InstallFolder)LPs" -Filter *.cab | % {
	Add-Log -Message "Adding language pack: $($_.FullName)"
	Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName
}


# STEP 8: Change language
If($Config.Config.Language) {
	Add-Log -Message "Configuring language using: $($Config.Config.Language)"
	& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$($InstallFolder)$($Config.Config.Language)`""
}


# STEP 9: Add features on demand
If($Config.Config.AddFeatures.Feature.Count -gt 0){
	$CurrentWU = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
	If($CurrentWU -eq 1){
		Add-Log -Message "Turning off WSUS"
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 0
		Restart-Service wuauserv
	}
	
	$Config.Config.AddFeatures.Feature | ForEach-Object {
		Add-Log -Message "Adding Windows feature: $_"
		Add-WindowsCapability -Online -Name $_ -ErrorAction SilentlyContinue
	}
	
	If($CurrentWU -eq 1){
		Add-Log -Message "Turning on WSUS"
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 1
		Restart-Service wuauserv
	}
}



# STEP 10: Customize default apps
# Export default app associations: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/export-or-import-default-application-associations?view=windows-11
If($Config.Config.DefaultApps) {
	Add-Log -Message "Setting default apps: $($Config.Config.DefaultApps)"
	& Dism.exe /Online /Import-DefaultAppAssociations:`"$($InstallFolder)$($Config.Config.DefaultApps)`"
}


# STEP 11: Set registered user and organization
If($Config.Config.RegisteredOwner){
	Add-Log -Message "Configuring registered user information"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "$($Config.Config.RegisteredOwner)" /f /reg:64 | Out-Host
}
If($Config.Config.RegisteredOrganization){
	Add-Log -Message "Configuring registered organization information"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "$($Config.Config.RegisteredOrganization)" /f /reg:64 | Out-Host
}


# STEP 12: Configure OEM branding info
If($Config.Config.OEMInfo){
	Add-Log -Message "Configuring OEM branding info"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /t REG_SZ /d "$($Config.Config.OEMInfo.Manufacturer)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /t REG_SZ /d "$($Config.Config.OEMInfo.Model)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /t REG_SZ /d "$($Config.Config.OEMInfo.SupportPhone)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /t REG_SZ /d "$($Config.Config.OEMInfo.SupportHours)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /t REG_SZ /d "$($Config.Config.OEMInfo.SupportURL)" /f /reg:64 | Out-Host
	Copy-Item "$InstallFolder\$($Config.Config.OEMInfo.Logo)" "C:\Windows\$($Config.Config.OEMInfo.Logo)" -Force
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "C:\Windows\$($Config.Config.OEMInfo.Logo)" /f /reg:64 | Out-Host
}


# STEP 13: Enable UE-V
Add-Log -Message "Enabling UE-V"
Enable-Uev
Set-UevConfiguration -Computer -SettingsStoragePath "%OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
Get-ChildItem "$($InstallFolder)UEV" -Filter *.xml | % {
	Add-Log -Message "Registering template: $($_.FullName)"
	Register-UevTemplate -Path $_.FullName
}


# STEP 14: Disable network location fly-out
Add-Log -Message "Turning off network location fly-out"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f


# Create a tag file just so Intune knows this was installed
If(-not (Test-Path "$($env:ProgramData)\Microsoft\AutopilotBranding")){
    #Mkdir "$($env:ProgramData)\Microsoft\AutopilotBranding"
	New-Item -Path "$($env:ProgramData)\Microsoft\AutopilotBranding" -Type Directory -Force
}
Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"


Write-Output -InputObject "Success"

Stop-Transcript

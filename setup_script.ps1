
$path = $env:APPDATA
$config = {
<#
#######################################################################################################################################################################################################################################################################################################################################################################################################################################################################

Function Declaration

#######################################################################################################################################################################################################################################################################################################################################################################################################################################################################
#>
function Show-BalloonTip {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $Text,

        [Parameter(Mandatory=$true)]
        [String]
        $Title,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Info","Warning","Error","None")]
        $Icon = "Info",

        [Parameter(Mandatory=$false)]
        [ValidateRange(1,6000)]
        [Int]
        $Seconds = 10

    )
    Add-Type -AssemblyName System.Windows.Forms
    if ($script:balloonToolTip -eq $null) {
        $script:balloonToolTip = New-Object System.Windows.Forms.NotifyIcon
    }
    $path = Get-Process -id $pid | Select-Object -ExpandProperty Path
    $balloonToolTip.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balloonToolTip.BalloonTipIcon = $Icon
    $balloonToolTip.BalloonTipText = $Text
    $balloonToolTip.BalloonTipTitle = $Title
    $balloonToolTip.Visible = $true
    $balloonToolTip.ShowBalloonTip($Seconds * 1000)
}


<#
#######################################################################################################################################################################################################################################################################################################################################################################################################################################################################

VPN Script

#######################################################################################################################################################################################################################################################################################################################################################################################################################################################################
#>

Show-BalloonTip -Text "Configuring VPN ..." -Title "Status"

# logging variables
$logfilepath = "$env:USERPROFILE\AppData\Local\Temp"
$logfilename = "_vpn_setup.log"
New-Item -Path $logfilepath -Name $logfilename -ItemType File -Force
$logfilefullpath = Get-Item -Path $logfilepath\$logfilename | Select-Object -ExpandProperty FullName

# script variable
$connectionName = "My VPN"
$hostname = "vpn.example.com"

# Configure security of dynamic Diffie-Hellman parameters
Show-BalloonTip -Text "Configuring security parameters ..." -Title "Status"

$date = Get-Date
"Configuring security parameters ... $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500

$date = Get-Date
"Checking registry key for strong DH parameters ... $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500

Try {
    $currentValue = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Rasman\Parameters" -Name NegotiateDH2048_AES256 -ErrorAction Stop
}
Catch {
    $currentValue = $null
}

If ($currentValue -eq $null) {
    $date = Get-Date
    "Registry key for strong DH could not be found. $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    $date = Get-Date
    "Attempting to write registry key ... $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    Try {
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Rasman\Parameters" -Name NegotiateDH2048_AES256 -Value 1 -PropertyType DWORD -ErrorAction Stop
        $registrySuccess = $true
        $date = Get-Date
        "Successfully wrote registry key for strong DH parameters! $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    }
    Catch {
        $registrySuccess = $false
        $date = Get-Date
        "Could not write registry key for strong DH parameters. $($_.Exception.Message) $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    }
}
ElseIf ($currentValue -ne 1) {
    $date = Get-Date
    "Registry key for strong DH was found, but parameters not enabled. $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    $date = Get-Date
    "Attempting to enable strong DH parameters ... $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    Try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Rasman\Parameters" -Name NegotiateDH2048_AES256 -Value 1 -ErrorAction Stop
        $registrySuccess = $true
        $date = Get-Date
        "Successfully configured registry key for strong DH parameters! $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    }
    Catch {
        $registrySuccess = $false
        $date = Get-Date
        "Could not modify registry key for strong DH parameters. $($_.Exception.Message) $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    }
}

<#
# If dynamic negotiation security configuration fails, attempt to set static DH/PFS parameters (not sure this will fix it, but worth a shot!)
If ($registrySuccess -ne $true) {
    $date = Get-Date
    "Attempting manually specify IPSec cipher suite ... $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    Try {
        Set-VpnConnectionIPsecConfiguration -ConnectionName $connectionName -DHGroup ECP256 -PfsGroup ECP256 -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA256 -Force
        $ipsecconfSucceeded = $true
        $date = Get-Date
        "Successfully modified IPSec cipher suite for VPN! (KeyEx=ECP256,Cipher=AESGCM256,Integ=SHA256/AESGCM256HMAC) $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    }
    Catch {
        $ipsecconfSucceeded = $false
        $date = Get-Date
        "Could not modify IPSec cipher suite configuration. $($_.Exception.Message) $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    }
}
Start-Sleep -Seconds 10
#>
#Start-Sleep -Seconds 10

If ($registrySuccess -eq $true) {
    Try {
        Add-VpnConnection -Name $connectionName -ServerAddress $hostname -TunnelType Ikev2 -EncryptionLevel Maximum -ErrorAction Stop
        $vpnsuccess = $true
        $date = Get-Date
        "Successfully configured virtual private network adapter! $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    }
    Catch {
        $vpnsuccess = $false
        $date = Get-Date
        "Could not create virtual private network adapter. $($_.Exception.Message) $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    }
}
Else {
    Show-BalloonTip -Text "VPN configuration failed." -Title "Failure" -Icon Error
    $date = Get-Date
    "FAILED - could not configure VPN. $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
    #exit
}

If ($vpnsuccess -eq $true) {
    Show-BalloonTip -Text "VPN configuration succeeded!" -Title "Complete"
    $date = Get-Date
    "Successfully configured VPN! $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
$MessageBox = [System.Windows.Forms.MessageBox]::Show(
    "VPN was configured successfully!","VPN Configuration","OK","Information"
)
}
Else {
    Show-BalloonTip -Text "VPN configuration failed." -Title "Failure" -Icon Error
    $date = Get-Date
    "FAILED - could not configure VPN. $date" | Out-File -FilePath $logfilefullpath -Append -Force -Encoding ascii -Width 500
$MessageBox = [System.Windows.Forms.MessageBox]::Show(
    "VPN configuration failed. Check the log file at %USERPROFILE%\AppData\Local\Temp\_vpn_setup.log","VPN Configuration","OK","Error"
)
}
}

New-Item -Path $path -Name config.ps1 -ItemType File -Value $config -Force
Start-Process -FilePath powershell.exe -ArgumentList "-ExecutionPolicy Bypass $path\config.ps1" -Verb RunAs -WindowStyle Hidden -Wait
Remove-Item -Path $path\config.ps1 -Force

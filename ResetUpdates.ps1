#To us an AD OU, remove the comments from $OU and $computers (ensuring to comment out the $computers array).
#$OU = "AD INFO HERE"
#$computers = Get-ADComputer -Filter * -SearchBase $OU | Select-Object Name | Foreach {$_.Name}
$psexec = "C:\scripts\SysInternals"
$computers = 'ARRAY OF COMPUTERS'
$fileDump = "C:\scripts\Dump"
foreach ($computer in $computers)
    {
    $PingResult = Test-Connection -ComputerName $computer -Count 1 -Quiet
		If($PingResult)
		{
            $arch = Get-WMIObject -Class Win32_Processor -ComputerName $computer | Select-Object AddressWidth

            Write-Host "1) Enabling PSRemoting..."
            & $psexec\PsExec.exe -nobanner \\$computer -s powershell "Enable-PSRemoting -Force" 2>&1 | Out-Null
 
            Write-Host "2) Stopping Windows Update Services..."
            $services = @('BITS','wuauserv','appidsvc')
            $remoteService = $null
            foreach ($service in $services)
                {
                    $remoteService = Get-Service -ComputerName $computer -Name $service
                    If ($remoteService.status -ne 'Stopped')
                    {
                        $remoteService.Stop()
                        Write-Host "Stopped $service..."
                    }
                }
 
            Write-Host "3) Remove QMGR Data file..."
            Invoke-Command -ComputerName $computer -ScriptBlock {Get-ChildItem -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" | Remove-Item -Force -Confirm:$False}
 
            Write-Host "4) Renaming the Software Distribution and CatRoot Folder..."
            Invoke-Command -ComputerName $computer -ScriptBlock {Rename-Item $env:systemroot\SoftwareDistribution SoftwareDistribution.bak -ErrorAction SilentlyContinue}
            Invoke-Command -ComputerName $computer -ScriptBlock {Rename-Item $env:systemroot\System32\Catroot2 catroot2.bak -ErrorAction SilentlyContinue}
 
            Write-Host "5) Removing old Windows Update log..." 
            Invoke-Command -ComputerName $computer -ScriptBlock {Remove-Item $env:systemroot\WindowsUpdate.log -ErrorAction SilentlyContinue}
 
            Write-Host "6) Resetting the Windows Update Services to defualt settings..." 
            Invoke-Command -ComputerName $computer -ScriptBlock {"sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"}
            Invoke-Command -ComputerName $computer -ScriptBlock {"sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"}
 
            Invoke-Command -ComputerName $computer -ScriptBlock {Set-Location $env:systemroot\system32}
 
            Write-Host "7) Registering some DLLs..."
            $DLLs = @('atl.dll','urlmon.dll','mshtml.dll','shdocvw.dll','browseui.dll','jscript.dll','vbscript.dll','scrrun.dll','msxml.dll','msxml3.dll','msxml6.dll','actxprxy.dll','softpub.dll','wintrust.dll','dssenh.dll','rsaenh.dll','gpkcsp.dll','sccbase.dll','slbcsp.dll','cryptdlg.dll','oleaut32.dll','ole32.dll','shell32.dll','initpki.dll','wuapi.dll','wuaueng.dll','wuaueng1.dll','wucltui.dll','wups.dll','wups2.dll','wuweb.dll','qmgr.dll','qmgrprxy.dll','wucltux.dll','muweb.dll','wuwebv.dll')
                
                Invoke-Command -ComputerName $computer -ScriptBlock {
                    foreach ($DLL in $using:DLLs){
                        regsvr32.exe /s "$dll"
                    }
                } 
 
            Write-Host "8) Removing WSUS client settings..."
            $values = @('AccountDomainSid','PingID','SusClientId')
            $regkeypath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"

            foreach ($value in $values)
                {
                    $testValue = Invoke-Command -ComputerName $computer -ScriptBlock {(Get-ItemProperty $using:regkeypath).$using:value -eq $null}
                    If ($testValue -eq $False)
                    {
                        Invoke-Command -ComputerName $computer -ScriptBlock {Remove-ItemProperty -path $using:regkeypath -name $using:value}
                        Write-Host "The value $value was deleted."
                    }
                    Else
                    {
                        Write-Host "The value $value does not exist."
                    }
                }
 
            Write-Host "9) Resetting the WinSock..." 
            Invoke-Command -ComputerName $computer -ScriptBlock {netsh winsock reset}
            Invoke-Command -ComputerName $computer -ScriptBlock {netsh winhttp reset proxy}
 
            Write-Host "10) Delete all BITS jobs..." 
            Invoke-Command -ComputerName $computer -ScriptBlock {Get-BitsTransfer | Remove-BitsTransfer}
 
            Write-Host "11) Starting Windows Update Services..."
            $services = @('BITS','wuauserv','appidsvc')
            $remoteService = $null
            foreach ($service in $services)
                {
                    $remoteService = Get-Service -ComputerName $computer -Name $service
                    If ($remoteService.status -ne 'Running')
                    {
                        $remoteService.Start()
                        Write-Host "Starting $service..."
                    }
                }
 
            Write-Host "12) Forcing discovery..." 
            Invoke-Command -ComputerName $computer -ScriptBlock {wuauclt /resetauthorization /detectnow}

            Write-Host "13) Setting reboot time..."
            Invoke-Command -ComputerName $computer -ScriptBlock {$Trigger = New-ScheduledTaskTrigger -At 11:00pm -Once
                $User = "NT AUTHORITY\SYSTEM"
                $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "Restart-Computer -Force"
                Register-ScheduledTask -TaskName "Restart Machine" -Trigger $Trigger -User $user -Action $Action -RunLevel Highest -Force}

            Write-Host "14) Disabling PSRemoting..."
            & $psexec\PsExec.exe -nobanner \\$computer -s powershell "Disable-PSRemoting -Force" 2>&1 | Out-Null

        }
        Else
        {
            Write-Host "$computer isn't responding. Skipping..."
            Out-File -append -FilePath $fileDump\skipped.txt -InputObject $computer
        }
    }
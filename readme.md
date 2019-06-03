# Reset Updates  

Please note: This script requires PSExec to function in it's current iteration.  
This PowerShell script will scan all devices in an OU or Array and find active devices.  
Active devices will have PSRemoting enabled temporarily.  
Once enabled, the Windows Update Client settings will be reset.  
Once reset, the machine will be scheduled for reboot at 11PM and PSRemoting is disabled.  
Any inactive devices will have their computer name dumped into a text file.
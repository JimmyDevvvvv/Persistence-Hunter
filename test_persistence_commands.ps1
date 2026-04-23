# ============================================================
# Persistence Hunter — Live Test Commands (No Admin Required)
# Run in a normal PowerShell window
# Sysmon must be running for chain correlation to work
# ============================================================


# ── 1. PowerShell encoded run key (APT29/Kimsuky style) ─────────────────────
# Chain: explorer.exe → powershell.exe → reg.exe
# Hits:  encoded_command, hidden_window, no_profile_flag, lolbin_chain
schtasks /create /tn "TestTaskPersist" /tr "powershell.exe -nop -w hidden -enc dGVzdA==" /sc onlogon /f


# ── 2. cmd.exe writing run key directly ─────────────────────────────────────
# Chain: explorer.exe → cmd.exe → reg.exe
# Hits:  lolbin_chain, suspicious_path (C:\Users\Public)
cmd.exe /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestCmdPersist" /d "C:\Users\Public\totally_not_malware.exe" /f


# ── 3. cmd.exe creating a scheduled task ────────────────────────────────────
# Chain: explorer.exe → cmd.exe → schtasks.exe
# Hits:  lolbin_chain, suspicious_path
cmd.exe /c schtasks /create /tn "WindowsUpdateHelper" /tr "C:\Users\Public\update.exe" /sc onlogon /f


# ── 4. PowerShell → schtasks (Cobalt Group style) ───────────────────────────
# Chain: explorer.exe → powershell.exe → schtasks.exe
# Hits:  APT-SIG-004, lolbin_chain
powershell.exe -nop -c "schtasks /create /tn 'NewChainTest' /tr 'rundll32.exe C:\Users\Public\payload.dll,EntryPoint' /sc onlogon /f"


# ── 5. Deep chain: cmd → powershell → schtasks (4 hops total) ───────────────
# Chain: explorer.exe → cmd.exe → powershell.exe → schtasks.exe
# Hits:  deep_chain, encoded_command, hidden_window
cmd.exe /c powershell.exe -nop -w hidden -c "schtasks /create /tn 'DeepChainTest' /tr 'C:\Windows\Temp\beacon.exe' /sc onlogon /f"


# ── 6. wscript.exe → reg.exe (script engine LOLBin, APT-SIG-003) ────────────
# Chain: explorer.exe → powershell.exe → wscript.exe → reg.exe
# Hits:  written_by_script_engine, lolbin_chain, APT29/Sandworm/FIN6
@"
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Run"" /v ""WscriptTest"" /d ""C:\Windows\Temp\implant.exe"" /f", 0, True
"@ | Out-File -FilePath "$env:TEMP\test_persist.vbs" -Encoding ASCII
wscript.exe "$env:TEMP\test_persist.vbs"


# ── 7. mshta.exe writing a run key (T1218.005) ───────────────────────────────
# Chain: explorer.exe → mshta.exe → reg.exe
# Hits:  lolbin_chain, temp_path
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MshtaTest /d C:\Windows\Temp\mshta_payload.exe /f"",0:close")


# ── 8. AppData run key, no suspicious flags (baseline) ───────────────────────
# Chain: explorer.exe → powershell.exe → reg.exe
# Hits:  appdata_path (+15) only — good low-score baseline to compare against
powershell.exe -nop -c "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v 'AppDataTest' /d ($env:APPDATA + '\Microsoft\update_helper.exe') /f"


# ── 9. rundll32 run key ──────────────────────────────────────────────────────
# Chain: explorer.exe → powershell.exe → reg.exe
# Hits:  APT-SIG-011 (rundll32 LOLBin), lolbin_chain
powershell.exe -nop -c "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v 'RundllTest' /d 'rundll32.exe C:\Users\Public\evil.dll,DllMain' /f"


# ── 10. Masquerading name (Lazarus/APT41 style) ───────────────────────────────
# Chain: explorer.exe → cmd.exe → reg.exe
# Hits:  masquerade_name (+25), APT-SIG-010/012
cmd.exe /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /d "C:\Users\Public\wuauclt.exe" /f


# ── 11. certutil → reg.exe chain (T1140) ─────────────────────────────────────
# Chain: explorer.exe → powershell.exe → certutil.exe then reg.exe
# Hits:  lolbin_chain, suspicious_path
powershell.exe -nop -c "
    certutil.exe -urlcache -split -f http://127.0.0.1/test C:\Windows\Temp\certutil_test.exe 2>null;
    reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v 'CertutilTest' /d 'C:\Windows\Temp\certutil_test.exe' /f
"


# ── 12. Scheduled task from AppData path (APT32/Lazarus) ─────────────────────
# Chain: explorer.exe → powershell.exe → schtasks.exe
# Hits:  appdata_path, APT-SIG-007, hidden_window
powershell.exe -nop -w hidden -c "schtasks /create /tn 'AppDataTask' /tr ($env:APPDATA + '\Microsoft\Teams\update.exe') /sc onlogon /f"


# ============================================================
# RUN YOUR COLLECTORS AFTER THE ABOVE:
# ============================================================
# python collector/registry_collector.py --scan --sysmon --events --hours 72 --chain-all
# python collector/task_collector.py     --scan --sysmon --events --hours 72 --chain-all
# python collector/service_collector.py  --scan --sysmon --events --hours 72 --chain-all
# python threat_scorer.py --summary


# ============================================================
# CLEANUP — paste this after you're done testing
# ============================================================

# Scheduled tasks
schtasks /delete /tn "TestTaskPersist"       /f
schtasks /delete /tn "WindowsUpdateHelper"   /f
schtasks /delete /tn "NewChainTest"          /f
schtasks /delete /tn "DeepChainTest"         /f
schtasks /delete /tn "AppDataTask"           /f

# Registry run keys
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestCmdPersist"  /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WscriptTest"     /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "MshtaTest"       /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AppDataTest"     /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "RundllTest"      /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate"   /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CertutilTest"    /f

# Temp files
Remove-Item "$env:TEMP\test_persist.vbs" -Force -ErrorAction SilentlyContinue
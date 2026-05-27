import re
import json
import logging
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger('threatiq')

# Path to the full APT profiles JSON shipped with the project
_ACTOR_JSON = Path(__file__).parent.parent / 'data' / 'actor_profiles.json'


# ══════════════════════════════════════════════════════════════
# BUILT-IN TTP PATTERN DATABASE
# ══════════════════════════════════════════════════════════════

TTP_PATTERNS: List[Dict] = [

    # ── Execution ──────────────────────────────────────────────
    {
        'pattern': r'powershell\s+.*-[Ee]nc(?:odedCommand)?',
        'technique_id': 'T1059.001', 'technique_name': 'PowerShell',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 92,
        'tools': ['PowerShell'], 'severity': 'high',
        'description': 'Base64 encoded PowerShell command detected'
    },
    {
        'pattern': r'powershell\s+.*-[Ww]indow[Ss]tyle\s+[Hh]idden',
        'technique_id': 'T1059.001', 'technique_name': 'PowerShell',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 88,
        'tools': ['PowerShell'], 'severity': 'high',
        'description': 'Hidden PowerShell window execution'
    },
    {
        'pattern': r'powershell\s+.*[Ii]nvoke-[Ee]xpression|powershell\s+.*\bIEX\b',
        'technique_id': 'T1059.001', 'technique_name': 'PowerShell',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 90,
        'tools': ['PowerShell'], 'severity': 'critical',
        'description': 'PowerShell IEX (Invoke-Expression) — common in fileless attacks'
    },
    {
        'pattern': r'powershell\s+.*[Dd]ownload[Ss]tring|powershell\s+.*[Ww]eb[Cc]lient',
        'technique_id': 'T1059.001', 'technique_name': 'PowerShell',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 91,
        'tools': ['PowerShell'], 'severity': 'critical',
        'description': 'PowerShell downloading remote payload'
    },
    {
        'pattern': r'\bcmd\.exe\b.*\/[Cc]\s+',
        'technique_id': 'T1059.003', 'technique_name': 'Windows Command Shell',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 75,
        'tools': ['cmd.exe'], 'severity': 'medium',
        'description': 'Command shell execution via cmd.exe /c'
    },
    {
        'pattern': r'\bwscript\.exe\b|\bcscript\.exe\b',
        'technique_id': 'T1059.005', 'technique_name': 'Visual Basic',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 80,
        'tools': ['WScript', 'CScript'], 'severity': 'high',
        'description': 'VBScript execution via wscript/cscript'
    },
    {
        'pattern': r'\bmshta\.exe\b',
        'technique_id': 'T1218.005', 'technique_name': 'Mshta',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 87,
        'tools': ['mshta.exe'], 'severity': 'high',
        'description': 'MSHTA used for proxy execution of malicious HTA'
    },
    {
        'pattern': r'\bwmic\b.*\bprocess\b.*\bcall\b.*\bcreate\b',
        'technique_id': 'T1047', 'technique_name': 'Windows Management Instrumentation',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 87,
        'tools': ['WMIC'], 'severity': 'high',
        'description': 'WMI process creation — commonly used for lateral movement'
    },
    {
        'pattern': r'\bpython\b.*-[Cc]\s+["\']?import\b|\bpython3?\b.*-[Cc]\s+',
        'technique_id': 'T1059.006', 'technique_name': 'Python',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 78,
        'tools': ['Python'], 'severity': 'medium',
        'description': 'Python used for command execution'
    },

    # ── Credential Access ──────────────────────────────────────
    {
        'pattern': r'\bmimikatz\b|\bsekurlsa\b|\blsadump\b',
        'technique_id': 'T1003.001', 'technique_name': 'LSASS Memory',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006', 'confidence': 97,
        'tools': ['Mimikatz'], 'severity': 'critical',
        'description': 'Mimikatz credential dumping tool detected'
    },
    {
        'pattern': r'\blsass\.exe\b.*dump|\bdump.*\blsass\.exe\b|procdump.*lsass',
        'technique_id': 'T1003.001', 'technique_name': 'LSASS Memory',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006', 'confidence': 95,
        'tools': ['ProcDump', 'Mimikatz'], 'severity': 'critical',
        'description': 'LSASS process memory dump detected'
    },
    {
        'pattern': r'EventID[:\s]+4625',
        'technique_id': 'T1110', 'technique_name': 'Brute Force',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006', 'confidence': 82,
        'tools': ['Various'], 'severity': 'high',
        'description': 'Multiple failed login attempts (EventID 4625)'
    },
    {
        'pattern': r'EventID[:\s]+4648',
        'technique_id': 'T1078', 'technique_name': 'Valid Accounts',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 75,
        'tools': ['Various'], 'severity': 'medium',
        'description': 'Logon with explicit credentials (EventID 4648)'
    },
    {
        'pattern': r'\bntds\.dit\b',
        'technique_id': 'T1003.003', 'technique_name': 'NTDS',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006', 'confidence': 96,
        'tools': ['Mimikatz', 'Secretsdump'], 'severity': 'critical',
        'description': 'NTDS.dit access — full AD credential dump'
    },
    {
        'pattern': r'\blaZagne\b|\blazagne\b',
        'technique_id': 'T1555', 'technique_name': 'Credentials from Password Stores',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006', 'confidence': 95,
        'tools': ['LaZagne'], 'severity': 'critical',
        'description': 'LaZagne password recovery tool detected'
    },
    {
        'pattern': r'\bHashcat\b|\bhashcat\b|\bjohn\s+the\s+ripper\b|\bjohntheripper\b',
        'technique_id': 'T1110.002', 'technique_name': 'Password Cracking',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006', 'confidence': 90,
        'tools': ['Hashcat', 'John the Ripper'], 'severity': 'high',
        'description': 'Password cracking tool detected'
    },

    # ── Defense Evasion ────────────────────────────────────────
    {
        'pattern': r'\bcertutil\b.*-(?:decode|urlcache|-urlcache)',
        'technique_id': 'T1140', 'technique_name': 'Deobfuscate/Decode Files or Information',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 90,
        'tools': ['certutil.exe'], 'severity': 'high',
        'description': 'Certutil used for decoding/downloading — common LOLBin abuse'
    },
    {
        'pattern': r'\bregsvr32\b.*\/[Ss]\s+.*\/[Nn]\s+|scrobj\.dll',
        'technique_id': 'T1218.010', 'technique_name': 'Regsvr32',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 88,
        'tools': ['regsvr32.exe'], 'severity': 'high',
        'description': 'Regsvr32 Squiblydoo technique for proxy execution'
    },
    {
        'pattern': r'\brundll32\b.*javascript:|rundll32.*shell32',
        'technique_id': 'T1218.011', 'technique_name': 'Rundll32',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 87,
        'tools': ['rundll32.exe'], 'severity': 'high',
        'description': 'Rundll32 proxy execution of malicious code'
    },
    {
        'pattern': r'Set-MpPreference.*-Disable|Add-MpPreference.*ExclusionPath',
        'technique_id': 'T1562.001', 'technique_name': 'Disable or Modify Tools',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 95,
        'tools': ['PowerShell'], 'severity': 'critical',
        'description': 'Windows Defender being disabled via PowerShell'
    },
    {
        'pattern': r'netsh\s+advfirewall\s+.*disable|netsh\s+firewall\s+set\s+opmode\s+disable',
        'technique_id': 'T1562.004', 'technique_name': 'Disable or Modify System Firewall',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 93,
        'tools': ['netsh'], 'severity': 'critical',
        'description': 'Windows Firewall being disabled'
    },
    {
        'pattern': r'\bwevtutil\b.*cl\s+|Clear-EventLog|Remove-EventLog',
        'technique_id': 'T1070.001', 'technique_name': 'Clear Windows Event Logs',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 93,
        'tools': ['wevtutil'], 'severity': 'critical',
        'description': 'Windows Event Logs being cleared to cover tracks'
    },
    {
        'pattern': r'EventID[:\s]+4688',
        'technique_id': 'T1059', 'technique_name': 'Command and Scripting Interpreter',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 72,
        'tools': ['Various'], 'severity': 'medium',
        'description': 'New process creation logged (EventID 4688)'
    },

    # ── Persistence ────────────────────────────────────────────
    {
        'pattern': r'\bschtasks\b.*\/[Cc][Rr][Ee][Aa][Tt][Ee]\b',
        'technique_id': 'T1053.005', 'technique_name': 'Scheduled Task',
        'tactic': 'Persistence', 'tactic_id': 'TA0003', 'confidence': 88,
        'tools': ['schtasks.exe'], 'severity': 'high',
        'description': 'Scheduled task creation for persistence'
    },
    {
        'pattern': r'\bnet\s+user\b.*\/add|\bnet\s+localgroup\b.*administrators',
        'technique_id': 'T1136.001', 'technique_name': 'Local Account',
        'tactic': 'Persistence', 'tactic_id': 'TA0003', 'confidence': 92,
        'tools': ['net.exe'], 'severity': 'critical',
        'description': 'New local user account created'
    },
    {
        'pattern': r'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        'technique_id': 'T1547.001', 'technique_name': 'Registry Run Keys / Startup Folder',
        'tactic': 'Persistence', 'tactic_id': 'TA0003', 'confidence': 88,
        'tools': ['reg.exe'], 'severity': 'high',
        'description': 'Registry Run key modification for persistence'
    },
    {
        'pattern': r'EventID[:\s]+4698',
        'technique_id': 'T1053.005', 'technique_name': 'Scheduled Task',
        'tactic': 'Persistence', 'tactic_id': 'TA0003', 'confidence': 85,
        'tools': ['Task Scheduler'], 'severity': 'high',
        'description': 'Scheduled task created (EventID 4698)'
    },
    {
        'pattern': r'\bsc\s+create\b|\bsc\s+config\b.*start=\s*auto',
        'technique_id': 'T1543.003', 'technique_name': 'Windows Service',
        'tactic': 'Persistence', 'tactic_id': 'TA0003', 'confidence': 87,
        'tools': ['sc.exe'], 'severity': 'high',
        'description': 'Malicious Windows service created for persistence'
    },

    # ── Privilege Escalation ───────────────────────────────────
    {
        'pattern': r'\bbypassuac\b|bypass.{0,10}uac|\bFodhelper\b|eventvwr.*reg',
        'technique_id': 'T1548.002', 'technique_name': 'Bypass User Account Control',
        'tactic': 'Privilege Escalation', 'tactic_id': 'TA0004', 'confidence': 93,
        'tools': ['Various'], 'severity': 'critical',
        'description': 'UAC bypass technique detected'
    },
    {
        'pattern': r'\bJuicyPotato\b|\bRoguePotato\b|\bPrintSpoofer\b|\bSweetPotato\b',
        'technique_id': 'T1134', 'technique_name': 'Access Token Manipulation',
        'tactic': 'Privilege Escalation', 'tactic_id': 'TA0004', 'confidence': 96,
        'tools': ['JuicyPotato', 'RoguePotato', 'PrintSpoofer'], 'severity': 'critical',
        'description': 'Token impersonation tool detected — SYSTEM privilege escalation'
    },
    {
        'pattern': r'\bbloodhound\b|\bSharpHound\b|\baclpwn\b',
        'technique_id': 'T1069.002', 'technique_name': 'Domain Groups',
        'tactic': 'Discovery', 'tactic_id': 'TA0007', 'confidence': 94,
        'tools': ['BloodHound', 'SharpHound'], 'severity': 'critical',
        'description': 'BloodHound/SharpHound AD enumeration detected'
    },

    # ── Lateral Movement ───────────────────────────────────────
    {
        'pattern': r'\bpsexec\b|\bPsExec\b',
        'technique_id': 'T1570', 'technique_name': 'Lateral Tool Transfer',
        'tactic': 'Lateral Movement', 'tactic_id': 'TA0008', 'confidence': 88,
        'tools': ['PsExec'], 'severity': 'high',
        'description': 'PsExec remote execution — common lateral movement tool'
    },
    {
        'pattern': r'\bpass.the.hash\b|\bpth\b.*\bntlm\b|sekurlsa::pth',
        'technique_id': 'T1550.002', 'technique_name': 'Pass the Hash',
        'tactic': 'Lateral Movement', 'tactic_id': 'TA0008', 'confidence': 95,
        'tools': ['Mimikatz'], 'severity': 'critical',
        'description': 'Pass-the-Hash attack detected'
    },
    {
        'pattern': r'EventID[:\s]+4624.*Logon Type[:\s]+3|Type\s+3\s+logon',
        'technique_id': 'T1021.002', 'technique_name': 'SMB/Windows Admin Shares',
        'tactic': 'Lateral Movement', 'tactic_id': 'TA0008', 'confidence': 75,
        'tools': ['Various'], 'severity': 'medium',
        'description': 'Network logon detected (Type 3) — possible lateral movement'
    },
    {
        'pattern': r'\bxfreerdp\b|\bremote\s+desktop\b|mstsc\.exe.*\/v:',
        'technique_id': 'T1021.001', 'technique_name': 'Remote Desktop Protocol',
        'tactic': 'Lateral Movement', 'tactic_id': 'TA0008', 'confidence': 78,
        'tools': ['mstsc.exe', 'xfreerdp'], 'severity': 'medium',
        'description': 'RDP remote desktop connection detected'
    },

    # ── Command & Control ──────────────────────────────────────
    {
        'pattern': r'\bcobalt.?strike\b|\bbeacon\b.*\bpipe\b|\bcs.{0,5}beacon\b',
        'technique_id': 'T1071.001', 'technique_name': 'Web Protocols',
        'tactic': 'Command and Control', 'tactic_id': 'TA0011', 'confidence': 95,
        'tools': ['Cobalt Strike'], 'severity': 'critical',
        'description': 'Cobalt Strike beacon detected'
    },
    {
        'pattern': r'\bmetasploit\b|\bmeterpreter\b|\bmsf\b.*\bpayload\b',
        'technique_id': 'T1059', 'technique_name': 'Command and Scripting Interpreter',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 94,
        'tools': ['Metasploit', 'Meterpreter'], 'severity': 'critical',
        'description': 'Metasploit/Meterpreter framework detected'
    },
    {
        'pattern': r'\bbitsadmin\b.*\/transfer|\bBITS\b.*transfer',
        'technique_id': 'T1197', 'technique_name': 'BITS Jobs',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 87,
        'tools': ['bitsadmin.exe'], 'severity': 'high',
        'description': 'BITS job used for file transfer — C2 or payload delivery'
    },
    {
        'pattern': r'curl\s+.*-[Oo]\s+.*\.(exe|bat|ps1|vbs|dll)|wget\s+.*\.(exe|bat|ps1)',
        'technique_id': 'T1105', 'technique_name': 'Ingress Tool Transfer',
        'tactic': 'Command and Control', 'tactic_id': 'TA0011', 'confidence': 85,
        'tools': ['curl', 'wget'], 'severity': 'high',
        'description': 'Suspicious file download via curl/wget'
    },
    {
        'pattern': r'\bdns.{0,15}tunnel|\bdnsx\b|\biodine\b|\bdnscat\b',
        'technique_id': 'T1071.004', 'technique_name': 'DNS',
        'tactic': 'Command and Control', 'tactic_id': 'TA0011', 'confidence': 92,
        'tools': ['DNScat', 'Iodine'], 'severity': 'critical',
        'description': 'DNS tunneling for C2 communication detected'
    },
    {
        'pattern': r'Empire\b|\bPowerShell\s+Empire\b',
        'technique_id': 'T1059.001', 'technique_name': 'PowerShell',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 94,
        'tools': ['PowerShell Empire'], 'severity': 'critical',
        'description': 'PowerShell Empire C2 framework detected'
    },
    {
        'pattern': r'\bchisel\b|\bngrok\b|\bfrp\b.*\bfrpc\b',
        'technique_id': 'T1572', 'technique_name': 'Protocol Tunneling',
        'tactic': 'Command and Control', 'tactic_id': 'TA0011', 'confidence': 91,
        'tools': ['Chisel', 'ngrok', 'FRP'], 'severity': 'critical',
        'description': 'Tunneling tool for firewall bypass detected'
    },

    # ── Discovery ──────────────────────────────────────────────
    {
        'pattern': r'\bnmap\b|\bnetdiscover\b|\barp-scan\b',
        'technique_id': 'T1046', 'technique_name': 'Network Service Discovery',
        'tactic': 'Discovery', 'tactic_id': 'TA0007', 'confidence': 83,
        'tools': ['nmap'], 'severity': 'medium',
        'description': 'Network scanning/discovery activity detected'
    },
    {
        'pattern': r'\bnet\s+view\b|\bnet\s+share\b|\bnet\s+group\b',
        'technique_id': 'T1135', 'technique_name': 'Network Share Discovery',
        'tactic': 'Discovery', 'tactic_id': 'TA0007', 'confidence': 80,
        'tools': ['net.exe'], 'severity': 'medium',
        'description': 'Network share enumeration detected'
    },
    {
        'pattern': r'\bwhoami\b|\bnet\s+user\b|\bnet\s+localgroup\b',
        'technique_id': 'T1033', 'technique_name': 'System Owner/User Discovery',
        'tactic': 'Discovery', 'tactic_id': 'TA0007', 'confidence': 75,
        'tools': ['whoami', 'net.exe'], 'severity': 'low',
        'description': 'User and group enumeration commands detected'
    },
    {
        'pattern': r'\bipconfig\b|\bifconfig\b|\barp\s+-[Aa]\b|\broute\s+print\b',
        'technique_id': 'T1016', 'technique_name': 'System Network Configuration Discovery',
        'tactic': 'Discovery', 'tactic_id': 'TA0007', 'confidence': 70,
        'tools': ['ipconfig', 'ifconfig'], 'severity': 'low',
        'description': 'Network configuration enumeration'
    },

    # ── Exfiltration ───────────────────────────────────────────
    {
        'pattern': r'\brclone\b.*copy|\brclone\b.*sync',
        'technique_id': 'T1567.002', 'technique_name': 'Exfiltration to Cloud Storage',
        'tactic': 'Exfiltration', 'tactic_id': 'TA0010', 'confidence': 90,
        'tools': ['rclone'], 'severity': 'critical',
        'description': 'rclone used for data exfiltration to cloud storage'
    },
    {
        'pattern': r'7z\b.*[Aa]\s+.*\.7z|rar\b.*[Aa]\s+.*\.rar|zip\b.*-[Rr]\b',
        'technique_id': 'T1560.001', 'technique_name': 'Archive via Utility',
        'tactic': 'Collection', 'tactic_id': 'TA0009', 'confidence': 78,
        'tools': ['7zip', 'WinRAR'], 'severity': 'medium',
        'description': 'Large archive creation — possible data staging for exfiltration'
    },

    # ── Ransomware / Impact ────────────────────────────────────
    {
        'pattern': r'\blockbit\b|\bREvil\b|\bconti\b|\bblackcat\b|\bALPHV\b',
        'technique_id': 'T1486', 'technique_name': 'Data Encrypted for Impact',
        'tactic': 'Impact', 'tactic_id': 'TA0040', 'confidence': 97,
        'tools': ['LockBit', 'REvil', 'Conti', 'BlackCat'], 'severity': 'critical',
        'description': 'Known ransomware family detected'
    },
    {
        'pattern': r'vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete',
        'technique_id': 'T1490', 'technique_name': 'Inhibit System Recovery',
        'tactic': 'Impact', 'tactic_id': 'TA0040', 'confidence': 96,
        'tools': ['vssadmin', 'wmic'], 'severity': 'critical',
        'description': 'Shadow copy deletion — ransomware recovery prevention'
    },
    {
        'pattern': r'bcdedit\s+\/set.*recoveryenabled\s+no|bcdedit.*safeboot',
        'technique_id': 'T1490', 'technique_name': 'Inhibit System Recovery',
        'tactic': 'Impact', 'tactic_id': 'TA0040', 'confidence': 95,
        'tools': ['bcdedit'], 'severity': 'critical',
        'description': 'Boot recovery disabled — ransomware technique'
    },

    # ── Web / Supply Chain ─────────────────────────────────────
    {
        'pattern': r'sqlmap|union\s+select|OR\s+1=1|DROP\s+TABLE',
        'technique_id': 'T1190', 'technique_name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access', 'tactic_id': 'TA0001', 'confidence': 88,
        'tools': ['sqlmap'], 'severity': 'critical',
        'description': 'SQL injection attack detected'
    },
    {
        'pattern': r'<script>.*alert\(|javascript:.*void\(|on\w+\s*=\s*["\']?javascript:',
        'technique_id': 'T1059.007', 'technique_name': 'JavaScript',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 82,
        'tools': ['Browser'], 'severity': 'high',
        'description': 'Cross-site scripting (XSS) payload detected'
    },

    # ── Windows Event IDs ──────────────────────────────────────
    {
        'pattern': r'EventID[:\s]+4657',
        'technique_id': 'T1112', 'technique_name': 'Modify Registry',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005', 'confidence': 80,
        'tools': ['reg.exe'], 'severity': 'high',
        'description': 'Registry modification detected (EventID 4657)'
    },
    {
        'pattern': r'EventID[:\s]+4104',
        'technique_id': 'T1059.001', 'technique_name': 'PowerShell',
        'tactic': 'Execution', 'tactic_id': 'TA0002', 'confidence': 82,
        'tools': ['PowerShell'], 'severity': 'high',
        'description': 'PowerShell Script Block Logging (EventID 4104)'
    },
]


# ══════════════════════════════════════════════════════════════
# APT ACTOR PROFILES  (fallback — full set loaded from JSON)
# ══════════════════════════════════════════════════════════════

# Minimal built-in fallback used only if actor_profiles.json cannot be read
_BUILTIN_APT_PROFILES: Dict = {
    'APT28':   {'aliases': ['Fancy Bear', 'Sofacy', 'STRONTIUM'], 'origin': 'Russia',       'motivation': 'espionage',         'tools': ['X-Agent', 'Mimikatz'],              'ttps': ['T1566', 'T1059.001', 'T1003.001']},
    'APT29':   {'aliases': ['Cozy Bear', 'NOBELIUM'],              'origin': 'Russia',       'motivation': 'espionage',         'tools': ['SUNBURST', 'Brute Ratel'],          'ttps': ['T1195.002', 'T1059.001', 'T1078']},
    'Lazarus': {'aliases': ['HIDDEN COBRA', 'APT38'],              'origin': 'North Korea',  'motivation': 'financial',         'tools': ['HOPLIGHT', 'BLINDINGCAN'],          'ttps': ['T1566', 'T1059', 'T1486']},
    'APT41':   {'aliases': ['Double Dragon', 'Winnti'],            'origin': 'China',        'motivation': 'espionage+financial','tools': ['ShadowPad', 'Cobalt Strike'],       'ttps': ['T1195', 'T1059.001', 'T1543.003']},
    'LockBit': {'aliases': ['LockBit 3.0'],                        'origin': 'Unknown',      'motivation': 'financial',         'tools': ['LockBit ransomware', 'rclone'],     'ttps': ['T1486', 'T1490', 'T1567.002']},
    'FIN7':    {'aliases': ['Carbanak', 'Navigator Group'],        'origin': 'Unknown',      'motivation': 'financial',         'tools': ['CARBANAK', 'Cobalt Strike'],        'ttps': ['T1566.001', 'T1059.007', 'T1055']},
    'Conti':   {'aliases': ['Wizard Spider'],                      'origin': 'Russia',       'motivation': 'financial',         'tools': ['Conti ransomware', 'TrickBot'],     'ttps': ['T1486', 'T1490', 'T1078']},
}

# Runtime profile store — populated at module load from JSON
APT_PROFILES: Dict = {}


def _load_actor_profiles() -> None:
    """
    FIX: Load the full APT actor profiles from data/actor_profiles.json.
    Falls back to built-in _BUILTIN_APT_PROFILES if file missing.
    Called once at module import time.
    """
    global APT_PROFILES
    if _ACTOR_JSON.exists():
        try:
            with open(_ACTOR_JSON, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            # The JSON may be a dict {name: profile} or a list [{name, ...}]
            if isinstance(raw, dict):
                APT_PROFILES = raw
            elif isinstance(raw, list):
                APT_PROFILES = {
                    item.get('name', item.get('actor_name', f'Actor_{i}')): item
                    for i, item in enumerate(raw)
                }
            logger.info(f"Loaded {len(APT_PROFILES)} APT profiles from {_ACTOR_JSON}")
            return
        except Exception as e:
            logger.warning(f"Could not load actor_profiles.json: {e} — using built-in fallback")
    else:
        logger.warning(f"actor_profiles.json not found at {_ACTOR_JSON} — using built-in fallback")

    APT_PROFILES = _BUILTIN_APT_PROFILES.copy()


# Load at import time
_load_actor_profiles()


# ══════════════════════════════════════════════════════════════
# PATTERN MATCHING ENGINE
# ══════════════════════════════════════════════════════════════

def match_patterns(text: str) -> List[Dict]:
    """
    Match input text against all TTP patterns.
    Returns list of matched TTPs sorted by confidence.
    """
    if not text:
        return []

    matched: Dict[str, Dict] = {}

    for pattern_def in TTP_PATTERNS:
        try:
            regex   = re.compile(pattern_def['pattern'], re.IGNORECASE | re.MULTILINE)
            matches = regex.findall(text)
            if not matches:
                continue

            tid = pattern_def['technique_id']

            if tid in matched:
                matched[tid]['match_count'] += len(matches)
                matched[tid]['confidence']   = min(
                    100,
                    matched[tid]['confidence'] + (len(matches) * 2)
                )
            else:
                matched[tid] = {
                    'technique_id':   tid,
                    'technique_name': pattern_def['technique_name'],
                    'tactic':         pattern_def['tactic'],
                    'tactic_id':      pattern_def['tactic_id'],
                    'confidence':     pattern_def['confidence'],
                    'tools_used':     pattern_def['tools'],
                    'severity':       pattern_def['severity'],
                    'description':    pattern_def['description'],
                    'match_count':    len(matches),
                    'source':         'pattern_db',
                }

        except re.error as e:
            logger.error(f"Regex error in pattern {pattern_def['technique_id']}: {e}")
            continue

    result = sorted(matched.values(), key=lambda x: x['confidence'], reverse=True)
    logger.info(f"Pattern DB matched {len(result)} TTPs")
    return result


def get_actor_profile(suspected_actor: str) -> Optional[Dict]:
    """Lookup APT actor profile by name or alias (case-insensitive)."""
    if not suspected_actor or suspected_actor.lower() in ('unknown', 'none', ''):
        return None

    query = suspected_actor.lower()

    for actor_name, profile in APT_PROFILES.items():
        if query in actor_name.lower():
            return {'name': actor_name, **profile}
        for alias in profile.get('aliases', []):
            if query in alias.lower():
                return {'name': actor_name, **profile}

    return None


def get_confidence_boost(matched_patterns: List[Dict]) -> int:
    """Calculate total confidence boost from pattern matches."""
    if not matched_patterns:
        return 0
    boost    = min(len(matched_patterns) * 3, 20)
    critical = sum(1 for p in matched_patterns if p.get('severity') == 'critical')
    boost   += min(critical * 2, 10)
    return min(boost, 25)


def load_external_patterns(json_path: str) -> int:
    """Load additional TTP patterns from an external JSON file."""
    path = Path(json_path)
    if not path.exists():
        logger.warning(f"External patterns file not found: {json_path}")
        return 0
    try:
        with open(path, 'r', encoding='utf-8') as f:
            external = json.load(f)
        existing_ids = {p['technique_id'] for p in TTP_PATTERNS}
        added = 0
        for pattern in external:
            if pattern.get('technique_id') not in existing_ids:
                TTP_PATTERNS.append(pattern)
                existing_ids.add(pattern['technique_id'])
                added += 1
        logger.info(f"Loaded {added} external patterns from {json_path}")
        return added
    except Exception as e:
        logger.error(f"Failed to load external patterns: {e}")
        return 0

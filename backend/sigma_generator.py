import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import yaml   # pip install pyyaml

logger = logging.getLogger('threatiq')

# ── Constants ──────────────────────────────────────────────────
AUTHOR  = 'ThreatIQ AI Engine'
STATUS  = 'experimental'
LICENSE = 'DRL 1.1'


# ══════════════════════════════════════════════════════════════
# SIGMA TEMPLATES PER TTP
# ══════════════════════════════════════════════════════════════

SIGMA_TEMPLATES: Dict[str, Dict] = {

    # ── PowerShell ─────────────────────────────────────────────
    'T1059.001': {
        'title'      : 'Suspicious PowerShell Encoded Command Execution',
        'description': 'Detects PowerShell execution with encoded commands — commonly used to obfuscate malicious scripts',
        'tags'       : ['attack.execution', 'attack.t1059.001'],
        'logsource'  : {'product': 'windows', 'service': 'powershell'},
        'detection'  : {
            'selection': {
                'EventID': 4104,
                'ScriptBlockText|contains': ['-enc', '-EncodedCommand', 'JAB', 'SQBFAFgA', 'SQBFAF']
            },
            'filter_legitimate': {
                'ScriptBlockText|contains': ['WindowsUpdate', 'PSWindowsUpdate']
            },
            'condition': 'selection and not filter_legitimate'
        },
        'falsepositives': ['Legitimate admin encoded scripts', 'Software deployment tools'],
        'level'      : 'high',
    },
    'T1059.001_iex': {
        'title'      : 'PowerShell Invoke-Expression Remote Download',
        'description': 'Detects IEX or Invoke-Expression downloading and executing remote content',
        'tags'       : ['attack.execution', 'attack.t1059.001', 'attack.t1105'],
        'logsource'  : {'product': 'windows', 'service': 'powershell'},
        'detection'  : {
            'selection': {
                'EventID': 4104,
                'ScriptBlockText|contains|all': ['IEX', 'DownloadString']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Very rare legitimate use'],
        'level'      : 'critical',
    },

    # ── Command Shell ──────────────────────────────────────────
    'T1059.003': {
        'title'      : 'Suspicious Windows Command Shell Execution',
        'description': 'Detects suspicious cmd.exe execution patterns used by attackers',
        'tags'       : ['attack.execution', 'attack.t1059.003'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': '\\cmd.exe',
                'CommandLine|contains': ['/c whoami', '/c net user', '/c ipconfig', '/c systeminfo']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate admin scripts', 'System management tools'],
        'level'      : 'medium',
    },

    # ── LSASS Credential Dumping ───────────────────────────────
    'T1003.001': {
        'title'      : 'LSASS Memory Credential Dumping',
        'description': 'Detects attempts to dump credentials from LSASS process memory',
        'tags'       : ['attack.credential_access', 'attack.t1003.001'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection_procdump': {
                'Image|endswith': '\\procdump.exe',
                'CommandLine|contains': 'lsass'
            },
            'selection_mimikatz': {
                'CommandLine|contains': ['sekurlsa', 'lsadump', 'mimikatz']
            },
            'selection_rundll': {
                'Image|endswith': '\\rundll32.exe',
                'CommandLine|contains': 'MiniDump'
            },
            'condition': '1 of selection_*'
        },
        'falsepositives': ['Authorized penetration testing'],
        'level'      : 'critical',
    },

    # ── Brute Force ────────────────────────────────────────────
    'T1110': {
        'title'      : 'Multiple Failed Logon Attempts — Brute Force',
        'description': 'Detects multiple failed logon attempts indicating brute force activity',
        'tags'       : ['attack.credential_access', 'attack.t1110'],
        'logsource'  : {'product': 'windows', 'service': 'security'},
        'detection'  : {
            'selection': {'EventID': 4625},
            'condition': 'selection | count() by TargetUserName > 10'
        },
        'falsepositives': ['Misconfigured services', 'Forgotten passwords'],
        'level'      : 'medium',
    },

    # ── Scheduled Task ─────────────────────────────────────────
    'T1053.005': {
        'title'      : 'Suspicious Scheduled Task Creation',
        'description': 'Detects creation of scheduled tasks used for persistence',
        'tags'       : ['attack.persistence', 'attack.t1053.005'],
        'logsource'  : {'product': 'windows', 'service': 'security'},
        'detection'  : {
            'selection_event': {'EventID': [4698, 4702]},
            'selection_cmd': {
                'Image|endswith': '\\schtasks.exe',
                'CommandLine|contains': '/create'
            },
            'filter_legitimate': {
                'TaskName|contains': ['\\Microsoft\\Windows\\', '\\Microsoft\\Office\\']
            },
            'condition': '(selection_event or selection_cmd) and not filter_legitimate'
        },
        'falsepositives': ['Software installation', 'System administration'],
        'level'      : 'high',
    },

    # ── New Local Account ──────────────────────────────────────
    'T1136.001': {
        'title'      : 'New Local User Account Created',
        'description': 'Detects creation of new local user accounts — common persistence technique',
        'tags'       : ['attack.persistence', 'attack.t1136.001'],
        'logsource'  : {'product': 'windows', 'service': 'security'},
        'detection'  : {
            'selection': {'EventID': 4720},
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate user provisioning', 'IT onboarding processes'],
        'level'      : 'high',
    },

    # ── Registry Run Keys ──────────────────────────────────────
    'T1547.001': {
        'title'      : 'Registry Run Key Persistence',
        'description': 'Detects modifications to registry Run keys used for persistence',
        'tags'       : ['attack.persistence', 'attack.t1547.001'],
        'logsource'  : {'product': 'windows', 'category': 'registry_set'},
        'detection'  : {
            'selection': {
                'TargetObject|contains': [
                    'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                    'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
                ]
            },
            'filter_legitimate': {
                'Image|startswith': ['C:\\Program Files\\', 'C:\\Windows\\System32\\']
            },
            'condition': 'selection and not filter_legitimate'
        },
        'falsepositives': ['Software installation adding startup entries'],
        'level'      : 'high',
    },

    # ── UAC Bypass ─────────────────────────────────────────────
    'T1548.002': {
        'title'      : 'UAC Bypass via Fodhelper or Event Viewer',
        'description': 'Detects common UAC bypass techniques used for privilege escalation',
        'tags'       : ['attack.privilege_escalation', 'attack.t1548.002'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection_fodhelper': {
                'ParentImage|endswith': '\\fodhelper.exe',
                'IntegrityLevel': 'High'
            },
            'selection_eventvwr': {
                'ParentImage|endswith': '\\eventvwr.exe',
                'CommandLine|contains': 'regedit'
            },
            'condition': '1 of selection_*'
        },
        'falsepositives': ['Very rare — almost always malicious'],
        'level'      : 'critical',
    },

    # ── Certutil Decode ────────────────────────────────────────
    'T1140': {
        'title'      : 'Certutil Used for File Decoding or Download',
        'description': 'Detects certutil.exe used to decode or download files — common LOLBin abuse',
        'tags'       : ['attack.defense_evasion', 'attack.t1140'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': '\\certutil.exe',
                'CommandLine|contains': ['-decode', '-urlcache', '-verifyctl']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate certificate operations'],
        'level'      : 'high',
    },

    # ── Defender Disable ───────────────────────────────────────
    'T1562.001': {
        'title'      : 'Windows Defender Disabled via PowerShell',
        'description': 'Detects attempts to disable Windows Defender using PowerShell cmdlets',
        'tags'       : ['attack.defense_evasion', 'attack.t1562.001'],
        'logsource'  : {'product': 'windows', 'service': 'powershell'},
        'detection'  : {
            'selection': {
                'EventID': 4104,
                'ScriptBlockText|contains': [
                    'Set-MpPreference -DisableRealtimeMonitoring',
                    'Set-MpPreference -DisableIOAVProtection',
                    'Add-MpPreference -ExclusionPath',
                    'Uninstall-WindowsFeature Windows-Defender'
                ]
            },
            'condition': 'selection'
        },
        'falsepositives': ['Authorized security configuration changes'],
        'level'      : 'critical',
    },

    # ── Event Log Clear ────────────────────────────────────────
    'T1070.001': {
        'title'      : 'Windows Event Logs Cleared',
        'description': 'Detects clearing of Windows Event Logs to cover attack tracks',
        'tags'       : ['attack.defense_evasion', 'attack.t1070.001'],
        'logsource'  : {'product': 'windows', 'service': 'security'},
        'detection'  : {
            'selection': {'EventID': [1102, 104]},
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate log management', 'Compliance log rotation'],
        'level'      : 'high',
    },

    # ── Regsvr32 ──────────────────────────────────────────────
    'T1218.010': {
        'title'      : 'Regsvr32 Proxy Execution (Squiblydoo)',
        'description': 'Detects regsvr32.exe used to proxy execution of malicious scripts',
        'tags'       : ['attack.defense_evasion', 'attack.t1218.010'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': '\\regsvr32.exe',
                'CommandLine|contains': ['/s', '/n', '/i:http', 'scrobj.dll']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate COM object registration'],
        'level'      : 'high',
    },

    # ── BITS Jobs ─────────────────────────────────────────────
    'T1197': {
        'title'      : 'BITS Job Used for Malicious File Transfer',
        'description': 'Detects bitsadmin used to transfer files — often used for C2 or payload delivery',
        'tags'       : ['attack.defense_evasion', 'attack.t1197'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': '\\bitsadmin.exe',
                'CommandLine|contains': ['/transfer', '/addfile', '/setnotifycmdline']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Windows Update', 'WSUS', 'Legitimate software updates'],
        'level'      : 'medium',
    },

    # ── Ingress Tool Transfer ──────────────────────────────────
    'T1105': {
        'title'      : 'Suspicious File Download via curl or wget',
        'description': 'Detects suspicious downloads of executable files via curl or wget',
        'tags'       : ['attack.command_and_control', 'attack.t1105'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': ['\\curl.exe', '\\wget.exe'],
                'CommandLine|contains': ['.exe', '.bat', '.ps1', '.vbs', '.dll']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate software downloads', 'Package managers'],
        'level'      : 'high',
    },

    # ── WMI Execution ─────────────────────────────────────────
    'T1047': {
        'title'      : 'WMI Process Creation for Lateral Movement',
        'description': 'Detects WMIC used to create processes — commonly used for lateral movement',
        'tags'       : ['attack.execution', 'attack.t1047'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': '\\wmic.exe',
                'CommandLine|contains': ['process call create', 'process where']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate WMI management', 'System administration scripts'],
        'level'      : 'high',
    },

    # ── Shadow Copy Deletion ───────────────────────────────────
    'T1490': {
        'title'      : 'Shadow Copies Deleted — Ransomware Indicator',
        'description': 'Detects deletion of shadow copies — strong ransomware indicator',
        'tags'       : ['attack.impact', 'attack.t1490'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection_vssadmin': {
                'Image|endswith': '\\vssadmin.exe',
                'CommandLine|contains': ['delete shadows', 'resize shadowstorage']
            },
            'selection_wmic': {
                'Image|endswith': '\\wmic.exe',
                'CommandLine|contains': 'shadowcopy delete'
            },
            'selection_bcdedit': {
                'Image|endswith': '\\bcdedit.exe',
                'CommandLine|contains': ['recoveryenabled no', 'bootstatuspolicy ignoreallfailures']
            },
            'condition': '1 of selection_*'
        },
        'falsepositives': ['Legitimate backup management — verify before action'],
        'level'      : 'critical',
    },

    # ── Data Encryption (Ransomware) ───────────────────────────
    'T1486': {
        'title'      : 'Data Encrypted for Impact — Ransomware Activity',
        'description': 'Detects mass file encryption activity indicative of ransomware',
        'tags'       : ['attack.impact', 'attack.t1486'],
        'logsource'  : {'product': 'windows', 'category': 'file_event'},
        'detection'  : {
            'selection': {
                'TargetFilename|endswith': [
                    '.locked', '.encrypted', '.crypt', '.WNCRY',
                    '.lockbit', '.conti', '.ryuk', '.ALPHV'
                ]
            },
            'condition': 'selection | count() > 20'
        },
        'falsepositives': ['Encryption software — verify context'],
        'level'      : 'critical',
    },

    # ── Pass the Hash ──────────────────────────────────────────
    'T1550.002': {
        'title'      : 'Pass-the-Hash Attack Detected',
        'description': 'Detects NTLM pass-the-hash lateral movement via suspicious logon patterns',
        'tags'       : ['attack.lateral_movement', 'attack.t1550.002'],
        'logsource'  : {'product': 'windows', 'service': 'security'},
        'detection'  : {
            'selection': {
                'EventID'         : 4624,
                'LogonType'       : 3,
                'AuthPackage'     : 'NTLM',
                'LogonProcessName': 'NtLmSsp'
            },
            'filter_legitimate': {
                'WorkstationName': '%Workstations%'
            },
            'condition': 'selection and not filter_legitimate'
        },
        'falsepositives': ['Legitimate NTLM network authentication'],
        'level'      : 'high',
    },

    # ── Network Scanning ───────────────────────────────────────
    'T1046': {
        'title'      : 'Network Service Scanning Activity',
        'description': 'Detects network scanning tools used for reconnaissance',
        'tags'       : ['attack.discovery', 'attack.t1046'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': ['\\nmap.exe', '\\masscan.exe', '\\zmap.exe'],
            },
            'condition': 'selection'
        },
        'falsepositives': ['Authorized network scanning', 'Vulnerability assessment tools'],
        'level'      : 'medium',
    },

    # ── Protocol Tunneling ─────────────────────────────────────
    'T1572': {
        'title'      : 'Protocol Tunneling Tool Detected',
        'description': 'Detects tunneling tools used to bypass network controls for C2',
        'tags'       : ['attack.command_and_control', 'attack.t1572'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': ['\\chisel.exe', '\\ngrok.exe', '\\frpc.exe', '\\plink.exe'],
            },
            'condition': 'selection'
        },
        'falsepositives': ['Authorized remote access tools'],
        'level'      : 'critical',
    },

    # ── DNS Tunneling ──────────────────────────────────────────
    'T1071.004': {
        'title'      : 'DNS Tunneling for C2 Communication',
        'description': 'Detects anomalous DNS query patterns indicating DNS tunneling',
        'tags'       : ['attack.command_and_control', 'attack.t1071.004'],
        'logsource'  : {'product': 'windows', 'service': 'dns-server'},
        'detection'  : {
            'selection': {
                'EventID'     : 256,
                'QueryName|re': r'.{50,}\.(com|net|org|io)'
            },
            'condition': 'selection | count() by ClientIP > 100'
        },
        'falsepositives': ['CDN traffic', 'Legitimate long domain names'],
        'level'      : 'high',
    },

    # ── Cloud Exfiltration ─────────────────────────────────────
    'T1567.002': {
        'title'      : 'Data Exfiltration to Cloud Storage via rclone',
        'description': 'Detects rclone tool used to exfiltrate data to cloud storage',
        'tags'       : ['attack.exfiltration', 'attack.t1567.002'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': '\\rclone.exe',
                'CommandLine|contains': ['copy', 'sync', 'move']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate cloud backup operations'],
        'level'      : 'high',
    },

    # ── BloodHound ─────────────────────────────────────────────
    'T1069.002': {
        'title'      : 'BloodHound / SharpHound AD Enumeration',
        'description': 'Detects BloodHound or SharpHound used to enumerate Active Directory',
        'tags'       : ['attack.discovery', 'attack.t1069.002'],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith'      : ['\\SharpHound.exe', '\\BloodHound.exe'],
                'CommandLine|contains': ['-CollectionMethod', '--CollectionMethods', 'All']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Authorized AD security assessments'],
        'level'      : 'critical',
    },

    # ── Linux Suspicious Commands ──────────────────────────────
    'T1059.004': {
        'title'      : 'Suspicious Linux Shell Commands',
        'description': 'Detects suspicious bash commands commonly used in Linux attacks',
        'tags'       : ['attack.execution', 'attack.t1059.004'],
        'logsource'  : {'product': 'linux', 'service': 'auditd'},
        'detection'  : {
            'selection': {
                'type'       : 'EXECVE',
                'a0|contains': ['bash', 'sh', 'python'],
                'a1|contains': ['-i', '-c', 'wget', 'curl', 'nc', 'ncat', '/dev/tcp']
            },
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate admin operations'],
        'level'      : 'high',
    },

    # ── Network C2 HTTP ───────────────────────────────────────
    'T1071.001': {
        'title'      : 'Suspicious Outbound HTTP/S — Possible C2 Beacon',
        'description': 'Detects regular outbound HTTP connections indicative of C2 beaconing',
        'tags'       : ['attack.command_and_control', 'attack.t1071.001'],
        'logsource'  : {'category': 'firewall', 'product': 'checkpoint'},
        'detection'  : {
            'selection': {
                'dst_port'     : [80, 443, 8080, 8443],
                'action'       : 'allow',
                'bytes_out|gte': 10000
            },
            'timeframe': '5m',
            'condition': 'selection | count() by src_ip > 20'
        },
        'falsepositives': ['Legitimate web browsing', 'Software updates', 'Cloud sync'],
        'level'      : 'medium',
    },
}

# Fallback generic template
GENERIC_TEMPLATE = {
    'title'      : 'Suspicious Activity — {technique_id} {technique_name}',
    'description': 'Auto-generated detection rule for {technique_name} ({technique_id})',
    'tags'       : ['attack.{tactic_tag}', 'attack.{technique_id_lower}'],
    'logsource'  : {'product': 'windows', 'category': 'process_creation'},
    'detection'  : {
        'selection': {'CommandLine|contains': '{keywords}'},
        'condition': 'selection'
    },
    'falsepositives': ['Legitimate use of this technique'],
    'level'      : 'medium',
}

TACTIC_TAGS: Dict[str, str] = {
    'Execution'            : 'execution',
    'Persistence'          : 'persistence',
    'Privilege Escalation' : 'privilege_escalation',
    'Defense Evasion'      : 'defense_evasion',
    'Credential Access'    : 'credential_access',
    'Discovery'            : 'discovery',
    'Lateral Movement'     : 'lateral_movement',
    'Collection'           : 'collection',
    'Command and Control'  : 'command_and_control',
    'Exfiltration'         : 'exfiltration',
    'Impact'               : 'impact',
    'Initial Access'       : 'initial_access',
    'Reconnaissance'       : 'reconnaissance',
}


# ══════════════════════════════════════════════════════════════
# GENERATOR
# ══════════════════════════════════════════════════════════════

_CONF_STR = {'critical': 95, 'high': 80, 'medium': 60, 'low': 30}

def _conf_to_int(c) -> int:
    """Normalise confidence to an integer 0-100 regardless of whether it
    was stored as a string ('high') or a number (82)."""
    if isinstance(c, (int, float)):
        return int(c)
    return _CONF_STR.get(str(c).lower().strip(), 50)


def _build_rule(ttp: Dict, template: Dict) -> Dict:
    """Build a complete SIGMA rule from template and TTP data."""
    now = datetime.now(timezone.utc)
    return {
        'title'         : template['title'],
        'id'            : f"threatiq-{ttp.get('technique_id','').lower().replace('.', '-')}-{now.strftime('%Y%m%d')}",
        'status'        : STATUS,
        'description'   : template['description'],
        'references'    : [f"https://attack.mitre.org/techniques/{ttp.get('technique_id', '').replace('.', '/')}/"],
        'author'        : AUTHOR,
        'date'          : now.strftime('%Y/%m/%d'),
        'modified'      : now.strftime('%Y/%m/%d'),
        'tags'          : template.get('tags', []),
        'license'       : LICENSE,
        'logsource'     : template['logsource'],
        'detection'     : template['detection'],
        'fields'        : ['CommandLine', 'Image', 'User', 'ComputerName'],
        'falsepositives': template.get('falsepositives', ['Unknown']),
        'level'         : template.get('level', 'medium'),
        'threatiq'      : {
            'technique_id'  : ttp.get('technique_id'),
            'technique_name': ttp.get('technique_name'),
            'tactic'        : ttp.get('tactic'),
            'confidence'    : ttp.get('confidence', 0),
            'tools'         : ttp.get('tools_used', ttp.get('tools', [])),
        }
    }


def _build_generic_rule(ttp: Dict) -> Dict:
    """Build a generic rule for TTPs without a specific template."""
    technique_id   = ttp.get('technique_id', 'UNKNOWN')
    technique_name = ttp.get('technique_name', 'Unknown Technique')
    tactic         = ttp.get('tactic', 'Unknown')

    # FIX Bug 1: tools_used/tools may be present but empty [].
    # .get() returns [] (not the default) when the key EXISTS with value [].
    # Must explicitly fall back to [technique_name] when the resolved list is empty.
    tools = ttp.get('tools_used', ttp.get('tools', [])) or [technique_name]

    # FIX Bug 2: tool names with spaces (e.g. "Cobalt Strike") produce invalid
    # Windows paths like \\cobalt strike.exe — strip spaces when building path.
    image_list = [
        f'\\{t.lower().replace(" ", "").replace("-", "")}.exe'
        for t in tools[:3] if t
    ]
    # Extra safety: if image_list is still somehow empty, use technique name
    if not image_list:
        image_list = [f'\\{technique_name.lower().replace(" ", "")}.exe']

    template = {
        'title'      : f'Suspicious Activity — {technique_id}: {technique_name}',
        'description': (
            f'Auto-generated detection rule for {technique_name} ({technique_id}). '
            f'Tactic: {tactic}. Known tools: {", ".join(tools[:3])}'
        ),
        'tags'       : [
            f'attack.{TACTIC_TAGS.get(tactic, tactic.lower().replace(" ", "_"))}',
            f'attack.{technique_id.lower().replace(".", "_")}',
        ],
        'logsource'  : {'product': 'windows', 'category': 'process_creation'},
        'detection'  : {
            'selection': {
                'Image|endswith': image_list,
            },
            'condition': 'selection'
        },
        'falsepositives': ['Legitimate use — verify context before action'],
        'level'      : (lambda c:
            'critical' if c >= 90 else
            'high'     if c >= 70 else 'medium'
        )(_conf_to_int(ttp.get('confidence', 0))),
    }
    return _build_rule(ttp, template)


def generate_sigma(ttps: List[Dict]) -> List[Dict]:
    """
    Generate SIGMA rules for a list of TTPs.
    Returns a list of SIGMA rule dicts.
    """
    if not ttps:
        return []

    rules       = []
    seen_titles = set()

    for ttp in ttps:
        # FIX: frontend SIGMA export maps technique_id → id; accept both fields
        technique_id = ttp.get('technique_id', '') or ttp.get('id', '')
        if not technique_id:
            continue
        # Ensure technique_id is set so _build_rule / _build_generic_rule work
        if 'technique_id' not in ttp or not ttp['technique_id']:
            ttp = dict(ttp)
            ttp['technique_id'] = technique_id

        # Look up exact template, then try base technique, then generic
        template = (
            SIGMA_TEMPLATES.get(technique_id) or
            SIGMA_TEMPLATES.get(technique_id.split('.')[0])
        )

        rule = (
            _build_rule(ttp, template) if template
            else _build_generic_rule(ttp)
        )

        # Deduplicate by title
        if rule['title'] not in seen_titles:
            rules.append(rule)
            seen_titles.add(rule['title'])

    logger.info(f"SIGMA: generated {len(rules)} rules from {len(ttps)} TTPs")
    return rules


def export_sigma_yaml(rules: List[Dict]) -> str:
    """Export SIGMA rules as a multi-document YAML string."""
    if not rules:
        return ''

    # FIX Bug 3: '---' is a YAML document START marker, not an end marker.
    # It must appear BEFORE each document, not after. The original code appended
    # '---' after yaml.dump() output (which already ends with '\n'), causing:
    #   (a) wrong placement — parsers may reject the file
    #   (b) double newlines between entries
    # Correct format: header comment + '---' + rule yaml, repeated per rule.

    header_lines = [
        f"# ThreatIQ Auto-Generated SIGMA Rules",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"# Rules: {len(rules)}",
        f"# Import into: Splunk, Elastic SIEM, QRadar, Microsoft Sentinel",
        f"# Author: {AUTHOR}",
    ]

    blocks = ['\n'.join(header_lines)]

    for i, rule in enumerate(rules, 1):
        comment = f"# Rule {i}/{len(rules)}: {rule['title']}"
        yaml_text = yaml.dump(rule, default_flow_style=False,
                              allow_unicode=True, sort_keys=False)
        # Each document: start marker → comment → yaml body
        blocks.append(f"---\n{comment}\n{yaml_text}")

    # Final end-of-stream marker
    blocks.append('...')

    return '\n'.join(blocks)


def save_sigma_file(rules: List[Dict], output_dir: str = None) -> str:
    """Save SIGMA rules to a YAML file and return the file path."""
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filename  = f'ThreatIQ_SIGMA_{timestamp}.yaml'
    filepath  = os.path.join(output_dir, filename)
    with open(filepath, 'w', encoding='utf-8') as fh:
        fh.write(export_sigma_yaml(rules))
    return filepath

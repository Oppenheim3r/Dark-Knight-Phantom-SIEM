"""
Dark Knight Phantom SIEM - Built-in Detection Rules
Carefully tuned rules with low false positive rates
"""

BUILTIN_RULES = [
    # ============================================================
    # AUTHENTICATION ATTACKS
    # ============================================================
    {
        "name": "Brute Force Attack - Failed Logons then Success",
        "description": "Detects multiple failed login attempts followed by a successful login, indicating a potential brute force attack that succeeded.",
        "severity": "HIGH",
        "rule_type": "SEQUENCE",
        "category": "AUTHENTICATION",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "mitre_subtechnique": "T1110.001",
        "cooldown_minutes": 30,
        "min_confidence": 75,
        "logic": {
            "track_by": "target_user",
            "window_minutes": 10,
            "exclude_system_accounts": True,
            "sequence": [
                {"event_id": 4625, "count": 5},  # 5+ failed logons
                {"event_id": 4624, "count": 1}   # then 1 success
            ],
            "track_unique": ["source_ip"]
        }
    },
    {
        "name": "Password Spray Attack",
        "description": "Detects failed login attempts from a single source IP against multiple different user accounts, indicating password spray attack.",
        "severity": "CRITICAL",
        "rule_type": "THRESHOLD",
        "category": "AUTHENTICATION",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "mitre_subtechnique": "T1110.003",
        "cooldown_minutes": 60,
        "min_confidence": 80,
        "logic": {
            "track_by": "source_ip",
            "window_minutes": 15,
            "event_ids": [4625],
            "threshold": 5,
            "unique_threshold": {
                "field": "target_user_name",
                "min": 5  # At least 5 different users
            },
            "track_unique": ["target_user_name", "hostname"]
        }
    },
    {
        "name": "Mass Account Lockouts",
        "description": "Detects multiple account lockouts in a short time, indicating potential attack or misconfiguration.",
        "severity": "HIGH",
        "rule_type": "THRESHOLD",
        "category": "AUTHENTICATION",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "cooldown_minutes": 30,
        "min_confidence": 70,
        "logic": {
            "track_by": "hostname",
            "window_minutes": 10,
            "event_ids": [4740],  # Account locked out
            "threshold": 5,
            "track_unique": ["target_user_name"]
        }
    },
    # DISABLED - Requires baseline learning which is not implemented yet
    # {
    #     "name": "Logon from Unusual Source",
    #     "description": "Detects successful logon from a source IP that has never been used before for this user (requires baseline).",
    #     "severity": "MEDIUM",
    #     ...
    # },
    
    # ============================================================
    # PRIVILEGE ESCALATION
    # ============================================================
    {
        "name": "User Added to Privileged Group",
        "description": "Detects when a user is added to sensitive groups like Domain Admins, Administrators, or Enterprise Admins.",
        "severity": "CRITICAL",
        "rule_type": "PATTERN",
        "category": "PRIVILEGE_ESCALATION",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078",
        "mitre_subtechnique": "T1078.002",
        "cooldown_minutes": 5,
        "min_confidence": 90,
        "logic": {
            "track_by": "target_user",
            "window_minutes": 5,
            "event_ids": [4728, 4732, 4756],  # Member added to security group
            "patterns": {
                "message": ["Domain Admins", "Administrators", "Enterprise Admins", 
                           "Schema Admins", "Account Operators", "Backup Operators"]
            },
            "required_matches": 1,
            "exclude_system_accounts": True
        }
    },
    {
        "name": "New Account Created and Added to Admins",
        "description": "Detects when a new account is created and quickly added to administrative groups.",
        "severity": "CRITICAL",
        "rule_type": "CORRELATION",
        "category": "PRIVILEGE_ESCALATION",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136",
        "cooldown_minutes": 60,
        "min_confidence": 85,
        "logic": {
            "track_by": "target_user",
            "window_minutes": 60,
            "required_events": [4720, 4732],  # Account created, added to group
            "exclude_system_accounts": True,
            "track_unique": ["user_name"]
        }
    },
    # DISABLED - Event 4672 fires for every admin logon, too many false positives
    # Would need to detect SPECIFIC dangerous privileges (SeDebugPrivilege) not just any privilege
    # {
    #     "name": "Special Privileges Assigned to New Logon",
    #     "description": "Detects when sensitive privileges (SeDebugPrivilege, etc.) are assigned during logon.",
    #     ...
    # },
    
    # ============================================================
    # LATERAL MOVEMENT
    # ============================================================
    {
        "name": "Lateral Movement via RDP",
        "description": "Detects a user making RDP connections to multiple hosts in a short time.",
        "severity": "HIGH",
        "rule_type": "THRESHOLD",
        "category": "LATERAL_MOVEMENT",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021",
        "mitre_subtechnique": "T1021.001",
        "cooldown_minutes": 30,
        "min_confidence": 75,
        "logic": {
            "track_by": "user_name",
            "window_minutes": 30,
            "event_ids": [4624],
            "logon_type": 10,  # RemoteInteractive (RDP)
            "threshold": 3,
            "unique_threshold": {
                "field": "hostname",
                "min": 3  # At least 3 different hosts
            },
            "exclude_system_accounts": True,
            "track_unique": ["hostname", "source_ip"]
        }
    },
    {
        "name": "Pass-the-Hash Detection",
        "description": "Detects NTLM authentication with NewCredentials logon type, which may indicate pass-the-hash attack.",
        "severity": "HIGH",
        "rule_type": "PATTERN",
        "category": "LATERAL_MOVEMENT",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1550",
        "mitre_subtechnique": "T1550.002",
        "cooldown_minutes": 15,
        "min_confidence": 70,
        "logic": {
            "track_by": "user_name",
            "window_minutes": 5,
            "event_ids": [4624],
            "patterns": {
                "logon_type": [9],  # NewCredentials
                "authentication_package": ["NTLM"]
            },
            "required_matches": 2,
            "exclude_system_accounts": True
        }
    },
    {
        "name": "Excessive SMB Share Access",
        "description": "Detects excessive access to SMB shares from a single source, may indicate reconnaissance or data exfiltration.",
        "severity": "MEDIUM",
        "rule_type": "THRESHOLD",
        "category": "LATERAL_MOVEMENT",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021",
        "mitre_subtechnique": "T1021.002",
        "cooldown_minutes": 30,
        "min_confidence": 65,
        "logic": {
            "track_by": "source_ip",
            "window_minutes": 15,
            "event_ids": [5140, 5145],  # Share accessed
            "threshold": 20,
            "unique_threshold": {
                "field": "object_name",  # Share name
                "min": 5
            },
            "track_unique": ["object_name", "user_name"]
        }
    },
    
    # ============================================================
    # PERSISTENCE
    # ============================================================
    {
        "name": "Suspicious Service Installation",
        "description": "Detects installation of services from suspicious paths (temp, user profile, etc.).",
        "severity": "CRITICAL",
        "rule_type": "PATTERN",
        "category": "PERSISTENCE",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1543",
        "mitre_subtechnique": "T1543.003",
        "cooldown_minutes": 5,
        "min_confidence": 85,
        "logic": {
            "track_by": "hostname",
            "window_minutes": 5,
            "event_ids": [7045],  # Service installed
            "patterns": {
                "process_path": [
                    "\\\\temp\\\\", "\\\\tmp\\\\", "\\\\appdata\\\\",
                    "\\\\users\\\\.*\\\\downloads\\\\",
                    "\\\\programdata\\\\(?!microsoft)",
                    "powershell", "cmd\\.exe", "wscript", "cscript",
                    "mshta", "rundll32"
                ]
            },
            "required_matches": 1
        }
    },
    {
        "name": "Multiple Scheduled Tasks Created",
        "description": "Detects multiple scheduled task creations in a short time, which may indicate malicious persistence.",
        "severity": "MEDIUM",
        "rule_type": "THRESHOLD",
        "category": "PERSISTENCE",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053",
        "mitre_subtechnique": "T1053.005",
        "cooldown_minutes": 30,
        "min_confidence": 70,
        "logic": {
            "track_by": "hostname",
            "window_minutes": 15,
            "event_ids": [4698],  # Scheduled task created
            "threshold": 3,  # 3+ tasks in 15 minutes is suspicious
            "exclude_system_accounts": True,
            "track_unique": ["user_name", "object_name"]
        }
    },
    {
        "name": "Registry Run Key Modified",
        "description": "Detects modifications to registry run keys commonly used for persistence.",
        "severity": "HIGH",
        "rule_type": "PATTERN",
        "category": "PERSISTENCE",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1547",
        "mitre_subtechnique": "T1547.001",
        "cooldown_minutes": 10,
        "min_confidence": 70,
        "logic": {
            "track_by": "hostname",
            "window_minutes": 5,
            "event_ids": [4657, 13],  # Registry value modified (Security + Sysmon)
            "patterns": {
                "object_name": [
                    "\\\\CurrentVersion\\\\Run",
                    "\\\\CurrentVersion\\\\RunOnce",
                    "\\\\CurrentVersion\\\\RunServices",
                    "\\\\Winlogon\\\\Shell",
                    "\\\\Winlogon\\\\Userinit"
                ]
            },
            "required_matches": 1
        }
    },
    
    # ============================================================
    # DEFENSE EVASION
    # ============================================================
    {
        "name": "Security Log Cleared",
        "description": "Detects when the Security event log is cleared, which is a critical indicator of compromise.",
        "severity": "CRITICAL",
        "rule_type": "THRESHOLD",
        "category": "DEFENSE_EVASION",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070",
        "mitre_subtechnique": "T1070.001",
        "cooldown_minutes": 60,
        "min_confidence": 50,  # Single event is definitive - always alert
        "logic": {
            "track_by": "hostname",
            "window_minutes": 5,
            "event_ids": [1102, 104],  # Security log cleared
            "threshold": 1,
            "exclude_system_accounts": False  # Always detect log clearing
        }
    },
    {
        "name": "Windows Defender Disabled",
        "description": "Detects when Windows Defender real-time protection is disabled.",
        "severity": "HIGH",
        "rule_type": "THRESHOLD",
        "category": "DEFENSE_EVASION",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562",
        "mitre_subtechnique": "T1562.001",
        "cooldown_minutes": 30,
        "min_confidence": 85,
        "logic": {
            "track_by": "hostname",
            "window_minutes": 5,
            "event_ids": [5001],  # Defender disabled
            "threshold": 1
        }
    },
    {
        "name": "Excessive Firewall Rule Modifications",
        "description": "Detects excessive modifications to Windows Firewall rules in a short time.",
        "severity": "MEDIUM",
        "rule_type": "THRESHOLD",
        "category": "DEFENSE_EVASION",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562",
        "mitre_subtechnique": "T1562.004",
        "cooldown_minutes": 30,
        "min_confidence": 70,
        "logic": {
            "track_by": "hostname",
            "window_minutes": 10,
            "event_ids": [4946, 4947, 4948, 4950],  # Firewall rule changes
            "threshold": 10,  # 10+ changes is suspicious (not Windows Update)
            "exclude_system_accounts": True,
            "track_unique": ["user_name"]
        }
    },
    
    # ============================================================
    # CREDENTIAL ACCESS
    # ============================================================
    # DISABLED - Requires Sysmon to be installed
    # {
    #     "name": "LSASS Memory Access",
    #     "description": "Detects processes accessing LSASS memory, which may indicate credential dumping.",
    #     ...
    # },
    {
        "name": "Kerberoasting Detected",
        "description": "Detects potential Kerberoasting attack - requesting TGS for service accounts.",
        "severity": "HIGH",
        "rule_type": "THRESHOLD",
        "category": "CREDENTIAL_ACCESS",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1558",
        "mitre_subtechnique": "T1558.003",
        "cooldown_minutes": 30,
        "min_confidence": 75,
        "logic": {
            "track_by": "user_name",
            "window_minutes": 10,
            "event_ids": [4769],  # Kerberos TGS request
            "threshold": 10,
            "unique_threshold": {
                "field": "service_name_kerberos",
                "min": 5  # 5+ different SPNs
            },
            "exclude_system_accounts": True,
            "track_unique": ["service_name_kerberos", "ticket_encryption_type"]
        }
    },
    
    # ============================================================
    # EXECUTION
    # ============================================================
    {
        "name": "Suspicious PowerShell Execution",
        "description": "Detects PowerShell commands with suspicious patterns (encoded, bypass, download).",
        "severity": "HIGH",
        "rule_type": "PATTERN",
        "category": "EXECUTION",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "mitre_subtechnique": "T1059.001",
        "cooldown_minutes": 10,
        "min_confidence": 75,
        "logic": {
            "track_by": "hostname",
            "window_minutes": 5,
            "event_ids": [4104, 4103],  # PowerShell script block logging
            "patterns": {
                "command_line": [
                    "-enc", "-encodedcommand", "frombase64",
                    "-exec bypass", "-executionpolicy bypass",
                    "invoke-expression", "iex\\s*\\(",
                    "downloadstring", "downloadfile",
                    "net\\.webclient", "invoke-webrequest",
                    "bitstransfer", "start-bitstransfer",
                    "reflection\\.assembly", "add-type"
                ]
            },
            "required_matches": 1
        }
    },
    # DISABLED - Requires Sysmon and can have false positives with legitimate tools
    # {
    #     "name": "Process Injection Detected",
    #     "description": "Detects potential process injection via CreateRemoteThread.",
    #     ...
    # },
]


def install_builtin_rules():
    """Install or update built-in detection rules"""
    from .models import DetectionRule
    
    created_count = 0
    updated_count = 0
    
    for rule_data in BUILTIN_RULES:
        rule, created = DetectionRule.objects.update_or_create(
            name=rule_data['name'],
            defaults={
                'description': rule_data['description'],
                'severity': rule_data['severity'],
                'rule_type': rule_data['rule_type'],
                'category': rule_data['category'],
                'logic': rule_data['logic'],
                'mitre_tactic': rule_data.get('mitre_tactic', ''),
                'mitre_technique': rule_data.get('mitre_technique', ''),
                'mitre_subtechnique': rule_data.get('mitre_subtechnique', ''),
                'cooldown_minutes': rule_data.get('cooldown_minutes', 15),
                'min_confidence': rule_data.get('min_confidence', 70),
                'is_builtin': True,
                'enabled': True,
            }
        )
        if created:
            created_count += 1
        else:
            updated_count += 1
    
    return created_count, updated_count


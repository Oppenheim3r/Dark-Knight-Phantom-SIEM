using System.Text.Json;

namespace PhantomAgent.Configuration;

/// <summary>
/// Agent configuration settings
/// </summary>
public class AgentConfig
{
    private static readonly string ConfigPath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, "config.json");

    public string AgentId { get; set; } = string.Empty;
    public string ServerUrl { get; set; } = "http://localhost:8000/api/v1/";
    public int CollectionIntervalSeconds { get; set; } = 10;
    public int HeartbeatIntervalSeconds { get; set; } = 30;
    public int BatchSize { get; set; } = 500;
    public int MaxEventsPerBatch { get; set; } = 1000;
    public bool CollectAllChannels { get; set; } = true;
    
    /// <summary>
    /// Windows Event Log channels to collect
    /// </summary>
    public List<string> EnabledChannels { get; set; } = new()
    {
        // Core Windows Logs
        "Security",
        "System",
        "Application",
        "Setup",
        
        // Active Directory
        "Directory Service",
        "DFS Replication",
        "DNS Server",
        "File Replication Service",
        
        // Security & Auditing
        "Microsoft-Windows-Security-Auditing",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "Microsoft-Windows-CodeIntegrity/Operational",
        
        // PowerShell
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
        "Windows PowerShell",
        
        // Sysmon (if installed)
        "Microsoft-Windows-Sysmon/Operational",
        
        // Remote Access
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        
        // Networking
        "Microsoft-Windows-SMBClient/Security",
        "Microsoft-Windows-SMBServer/Security",
        "Microsoft-Windows-DNS-Client/Operational",
        
        // WMI & Task Scheduler
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        
        // Kerberos & NTLM
        "Microsoft-Windows-Kerberos/Operational",
        "Microsoft-Windows-NTLM/Operational",
        
        // Certificate Services
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
        
        // LDAP
        "Microsoft-Windows-LDAP-Client/Debug",
        
        // Group Policy
        "Microsoft-Windows-GroupPolicy/Operational",
        
        // Bits (Background Transfer)
        "Microsoft-Windows-Bits-Client/Operational",
        
        // Windows Update
        "Microsoft-Windows-WindowsUpdateClient/Operational",
        
        // Hyper-V (if applicable)
        "Microsoft-Windows-Hyper-V-VMMS-Admin",
        "Microsoft-Windows-Hyper-V-Worker-Admin",
        
        // Printservice
        "Microsoft-Windows-PrintService/Operational",
    };

    /// <summary>
    /// Event IDs to always collect (critical security events)
    /// If empty, collects all events
    /// </summary>
    public List<int> CriticalEventIds { get; set; } = new()
    {
        // Logon Events
        4624, 4625, 4634, 4647, 4648, 4672, 4675,
        
        // Account Management
        4720, 4722, 4723, 4724, 4725, 4726, 4727,
        4728, 4729, 4730, 4731, 4732, 4733, 4734,
        4735, 4737, 4738, 4740, 4741, 4742, 4743,
        4754, 4755, 4756, 4757, 4758, 4764, 4765, 4766,
        
        // Process Events
        4688, 4689, 4696, 4697,
        
        // Service Events
        7045, 7034, 7035, 7036, 7040,
        
        // Scheduled Tasks
        4698, 4699, 4700, 4701, 4702,
        
        // Policy Changes
        4704, 4705, 4706, 4707, 4713, 4714, 4715, 4716, 4717, 4718, 4719, 4739,
        
        // Object Access
        4656, 4658, 4659, 4660, 4661, 4662, 4663, 4664, 4985,
        
        // Kerberos
        4768, 4769, 4770, 4771, 4772, 4773, 4776,
        
        // Network Shares
        5140, 5142, 5143, 5144, 5145, 5168,
        
        // Firewall
        5156, 5157, 5158, 5159,
        
        // AD DS
        5136, 5137, 5138, 5139, 5141,
        
        // Audit Log
        1102, 1100,
        
        // Sysmon Events (1-26)
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        
        // Windows Defender
        1006, 1007, 1008, 1116, 1117, 5001,
        
        // PowerShell
        4103, 4104, 4105, 4106,
    };

    public static AgentConfig Load()
    {
        if (File.Exists(ConfigPath))
        {
            try
            {
                var json = File.ReadAllText(ConfigPath);
                var config = JsonSerializer.Deserialize<AgentConfig>(json);
                if (config != null)
                {
                    // Generate agent ID if not set
                    if (string.IsNullOrEmpty(config.AgentId))
                    {
                        config.AgentId = GenerateAgentId();
                        config.Save();
                    }
                    return config;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading config: {ex.Message}");
            }
        }

        // Create default config
        var defaultConfig = new AgentConfig
        {
            AgentId = GenerateAgentId()
        };
        defaultConfig.Save();
        return defaultConfig;
    }

    public void Save()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        var json = JsonSerializer.Serialize(this, options);
        File.WriteAllText(ConfigPath, json);
    }

    private static string GenerateAgentId()
    {
        var hostname = Environment.MachineName.ToLower();
        var guid = Guid.NewGuid().ToString("N")[..8];
        return $"phantom-{hostname}-{guid}";
    }
}




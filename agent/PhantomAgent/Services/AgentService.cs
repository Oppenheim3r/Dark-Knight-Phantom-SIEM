using Microsoft.Extensions.Hosting;
using PhantomAgent.Collectors;
using PhantomAgent.Configuration;
using PhantomAgent.Transport;
using Serilog;

namespace PhantomAgent.Services;

/// <summary>
/// Main agent service - collects and sends Windows Event Logs
/// </summary>
public class AgentService : BackgroundService
{
    private readonly AgentConfig _config;
    private readonly WindowsEventCollector _collector;
    private readonly EventBatchSender _sender;
    private readonly SiemHttpClient _client;

    public AgentService(
        AgentConfig config,
        WindowsEventCollector collector,
        EventBatchSender sender,
        SiemHttpClient client)
    {
        _config = config;
        _collector = collector;
        _sender = sender;
        _client = client;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Log.Information("Agent ID: {AgentId}", _config.AgentId);
        Log.Information("Server URL: {ServerUrl}", _config.ServerUrl);
        Log.Information("Collection Interval: {Interval}s", _config.CollectionIntervalSeconds);
        Log.Information("Enabled Channels: {Count}", _config.EnabledChannels.Count);

        // Register with SIEM server
        await RegisterAgentAsync();

        // Wait a moment for registration to complete
        await Task.Delay(2000, stoppingToken);

        Log.Information("Starting event collection...");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Collect events
                var events = _collector.CollectEvents();
                
                if (events.Count > 0)
                {
                    Log.Information("Collected {Count} events from Windows Event Logs", events.Count);
                    _sender.QueueEvents(events);
                    
                    // Send queued events immediately
                    await _sender.SendQueuedEventsAsync();
                }
                else
                {
                    Log.Debug("No new events to collect");
                }

                // Wait for next collection cycle
                await Task.Delay(
                    TimeSpan.FromSeconds(_config.CollectionIntervalSeconds), 
                    stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error in collection cycle");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        Log.Information("Agent service stopped");
    }

    /// <summary>
    /// Register agent with the SIEM server
    /// </summary>
    private async Task RegisterAgentAsync()
    {
        Log.Information("Registering agent with SIEM server...");

        var registration = new PhantomAgent.Models.AgentRegistration
        {
            Hostname = Environment.MachineName,
            Domain = Environment.UserDomainName,
            Fqdn = GetFqdn(),
            IpAddress = GetLocalIpAddress() ?? "127.0.0.1",
            OsType = GetOsType(),
            OsVersion = Environment.OSVersion.VersionString,
            OsBuild = Environment.OSVersion.Version.Build.ToString(),
            Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86",
            IsDomainController = IsDomainController(),
            ServerRole = GetServerRole(),
            AgentVersion = "1.0.0",
            EnabledChannels = _config.EnabledChannels
        };

        try
        {
            var response = await _client.RegisterAsync(registration);
            
            if (response != null && response.Status == "success")
            {
                // Update agent ID with server-assigned ID
                if (!string.IsNullOrEmpty(response.AgentId))
                {
                    _config.AgentId = response.AgentId;
                }
                
                Log.Information("Agent registered successfully: {AgentId}", _config.AgentId);
                
                // Update config if server provided new settings
                if (response.Config != null)
                {
                    if (response.Config.CollectionInterval > 0)
                        _config.CollectionIntervalSeconds = response.Config.CollectionInterval;
                    if (response.Config.BatchSize > 0)
                        _config.BatchSize = response.Config.BatchSize;
                    // Only update channels if server provides a non-empty list
                    if (response.Config.EnabledChannels != null && response.Config.EnabledChannels.Count > 0)
                        _config.EnabledChannels = response.Config.EnabledChannels;
                }
                
                _config.Save();
            }
            else
            {
                Log.Warning("Agent registration response was unsuccessful");
            }
        }
        catch (Exception ex)
        {
            Log.Warning("Failed to register agent (will retry): {Error}", ex.Message);
        }
    }

    private string GetFqdn()
    {
        try
        {
            var domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            var hostName = System.Net.Dns.GetHostName();
            
            if (!string.IsNullOrEmpty(domainName))
                return $"{hostName}.{domainName}";
            
            return hostName;
        }
        catch
        {
            return Environment.MachineName;
        }
    }

    private string? GetLocalIpAddress()
    {
        try
        {
            var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
        }
        catch { }
        
        return null;
    }

    private string GetOsType()
    {
        var version = Environment.OSVersion.Version;
        
        // Check if Server
        if (IsWindowsServer())
        {
            return version.Build switch
            {
                >= 26100 => "WINDOWS_SERVER_2025",
                >= 20348 => "WINDOWS_SERVER_2022",
                >= 17763 => "WINDOWS_SERVER_2019",
                >= 14393 => "WINDOWS_SERVER_2016",
                _ => "WINDOWS_SERVER_2016"
            };
        }
        
        // Client OS
        return version.Build switch
        {
            >= 22000 => "WINDOWS_11",
            >= 10240 => "WINDOWS_10",
            _ => "OTHER"
        };
    }

    private bool IsWindowsServer()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var productName = key?.GetValue("ProductName")?.ToString();
            return productName?.Contains("Server") ?? false;
        }
        catch
        {
            return false;
        }
    }

    private bool IsDomainController()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\ProductOptions");
            var productType = key?.GetValue("ProductType")?.ToString();
            return productType == "LanmanNT";
        }
        catch
        {
            return false;
        }
    }

    private string GetServerRole()
    {
        if (IsDomainController())
            return "DOMAIN_CONTROLLER";
        
        if (IsWindowsServer())
        {
            // Check for specific roles
            try
            {
                // Check DNS
                if (System.IO.File.Exists(@"C:\Windows\System32\dns.exe"))
                    return "DNS_SERVER";
                
                // Check DHCP
                if (System.IO.File.Exists(@"C:\Windows\System32\dhcpssvc.dll"))
                    return "DHCP_SERVER";
                
                // Check IIS
                if (System.IO.Directory.Exists(@"C:\inetpub"))
                    return "WEB_SERVER";
                
                // Check Hyper-V
                if (System.IO.File.Exists(@"C:\Windows\System32\vmms.exe"))
                    return "HYPER_V_HOST";
            }
            catch { }
            
            return "MEMBER_SERVER";
        }
        
        return "WORKSTATION";
    }
}


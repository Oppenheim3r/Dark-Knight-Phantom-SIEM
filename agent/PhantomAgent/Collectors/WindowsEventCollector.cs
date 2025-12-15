using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using PhantomAgent.Configuration;
using PhantomAgent.Models;
using Serilog;

namespace PhantomAgent.Collectors;

/// <summary>
/// Collects Windows Event Logs from all configured channels
/// </summary>
public class WindowsEventCollector
{
    private readonly AgentConfig _config;
    private readonly string _hostname;
    private readonly Dictionary<string, DateTime> _lastReadTimes = new();
    private readonly object _lock = new();

    public WindowsEventCollector(AgentConfig config)
    {
        _config = config;
        _hostname = Environment.MachineName;
    }

    /// <summary>
    /// Collect events from all configured channels since last collection
    /// </summary>
    public List<SecurityEvent> CollectEvents()
    {
        var allEvents = new List<SecurityEvent>();

        foreach (var channel in _config.EnabledChannels)
        {
            try
            {
                var events = CollectFromChannel(channel);
                allEvents.AddRange(events);
            }
            catch (EventLogNotFoundException)
            {
                // Channel doesn't exist on this system, skip silently
            }
            catch (UnauthorizedAccessException)
            {
                Log.Warning("Access denied to channel: {Channel}", channel);
            }
            catch (Exception ex)
            {
                Log.Warning("Error collecting from {Channel}: {Error}", channel, ex.Message);
            }
        }

        // Sort by timestamp
        allEvents = allEvents.OrderBy(e => e.Timestamp).ToList();

        // Limit to max events per batch
        if (allEvents.Count > _config.MaxEventsPerBatch)
        {
            allEvents = allEvents.TakeLast(_config.MaxEventsPerBatch).ToList();
        }

        return allEvents;
    }

    /// <summary>
    /// Collect events from a specific channel
    /// </summary>
    private List<SecurityEvent> CollectFromChannel(string channel)
    {
        var events = new List<SecurityEvent>();
        
        lock (_lock)
        {
            // Get last read time for this channel
            if (!_lastReadTimes.TryGetValue(channel, out var lastReadTime))
            {
                // First run: get events from last 1 hour to ensure we capture recent activity
                lastReadTime = DateTime.UtcNow.AddHours(-1);
                Log.Debug("First collection from {Channel}, looking back 1 hour", channel);
            }

            var queryString = $"*[System[TimeCreated[@SystemTime >= '{lastReadTime:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";
            
            try
            {
                var query = new EventLogQuery(channel, PathType.LogName, queryString);
                
                using var reader = new EventLogReader(query);
                EventRecord? record;
                
                var newestTime = lastReadTime;

                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        try
                        {
                            var secEvent = ParseEventRecord(record, channel);
                            if (secEvent != null)
                            {
                                events.Add(secEvent);
                                
                                if (secEvent.Timestamp > newestTime)
                                {
                                    newestTime = secEvent.Timestamp;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Debug("Error parsing event {EventId}: {Error}", record.Id, ex.Message);
                        }
                    }
                }

                // Update last read time
                if (newestTime > lastReadTime)
                {
                    _lastReadTimes[channel] = newestTime.AddMilliseconds(1);
                }
            }
            catch (EventLogException ex)
            {
                Log.Warning("EventLog error for {Channel}: {Error}", channel, ex.Message);
            }
        }

        return events;
    }

    /// <summary>
    /// Parse an EventRecord into our SecurityEvent model
    /// </summary>
    private SecurityEvent? ParseEventRecord(EventRecord record, string channel)
    {
        var secEvent = new SecurityEvent
        {
            EventId = record.Id,
            EventRecordId = record.RecordId,
            Timestamp = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
            Channel = channel,
            ProviderName = record.ProviderName ?? string.Empty,
            ProviderGuid = record.ProviderId?.ToString() ?? string.Empty,
            Hostname = _hostname,
            Level = (int)(record.Level ?? 0),
            LevelName = GetLevelName(record.Level),
            Task = (int)(record.Task ?? 0),
            TaskName = record.TaskDisplayName ?? string.Empty,
            Opcode = (int)(record.Opcode ?? 0),
            OpcodeName = record.OpcodeDisplayName ?? string.Empty,
            Keywords = record.KeywordsDisplayNames != null 
                ? string.Join(",", record.KeywordsDisplayNames) 
                : string.Empty,
        };

        // Get formatted message
        try
        {
            secEvent.Message = record.FormatDescription() ?? string.Empty;
        }
        catch
        {
            secEvent.Message = string.Empty;
        }

        // Get raw XML
        try
        {
            secEvent.RawXml = record.ToXml();
            
            // Parse XML to extract detailed data
            ParseEventXml(secEvent, secEvent.RawXml);
        }
        catch (Exception ex)
        {
            Log.Debug("Error getting XML for event {EventId}: {Error}", record.Id, ex.Message);
        }

        // Get user information from the event
        if (record.UserId != null)
        {
            secEvent.UserSid = record.UserId.Value;
            try
            {
                var account = record.UserId.Translate(typeof(System.Security.Principal.NTAccount));
                var parts = account.ToString().Split('\\');
                if (parts.Length == 2)
                {
                    secEvent.UserDomain = parts[0];
                    secEvent.UserName = parts[1];
                }
                else
                {
                    secEvent.UserName = account.ToString();
                }
            }
            catch
            {
                // Unable to translate SID
            }
        }

        return secEvent;
    }

    /// <summary>
    /// Parse event XML to extract detailed data fields
    /// </summary>
    private void ParseEventXml(SecurityEvent secEvent, string xml)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            var ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;

            // Parse EventData
            var eventData = doc.Descendants(ns + "EventData").FirstOrDefault();
            if (eventData != null)
            {
                foreach (var data in eventData.Elements(ns + "Data"))
                {
                    var name = data.Attribute("Name")?.Value ?? "Value";
                    var value = data.Value;
                    secEvent.EventData[name] = value;
                }

        // Extract common fields
        ExtractCommonFields(secEvent);
    }

    // Parse UserData (for some events)
            var userData = doc.Descendants(ns + "UserData").FirstOrDefault();
            if (userData != null)
            {
                foreach (var element in userData.Descendants())
                {
                    if (!string.IsNullOrEmpty(element.Value))
                    {
                        secEvent.UserData[element.Name.LocalName] = element.Value;
                    }
                }
            }

            // Parse System data
            var system = doc.Descendants(ns + "System").FirstOrDefault();
            if (system != null)
            {
                var execution = system.Element(ns + "Execution");
                if (execution != null)
                {
                    if (int.TryParse(execution.Attribute("ProcessID")?.Value, out var pid))
                    {
                        secEvent.ProcessId = pid;
                    }
                }

                var computer = system.Element(ns + "Computer")?.Value;
                if (!string.IsNullOrEmpty(computer) && computer.Contains('.'))
                {
                    secEvent.Domain = computer.Split('.').Skip(1).FirstOrDefault();
                }
            }
        }
        catch (Exception ex)
        {
            Log.Debug("Error parsing event XML: {Error}", ex.Message);
        }
    }

    /// <summary>
    /// Extract common security fields from EventData
    /// </summary>
    private void ExtractCommonFields(SecurityEvent secEvent)
    {
        var data = secEvent.EventData;

        // User fields
        if (data.TryGetValue("TargetUserName", out var targetUser))
            secEvent.TargetUserName = targetUser?.ToString();
        if (data.TryGetValue("TargetDomainName", out var targetDomain))
            secEvent.TargetUserDomain = targetDomain?.ToString();
        if (data.TryGetValue("TargetUserSid", out var targetSid))
            secEvent.TargetUserSid = targetSid?.ToString();
        if (data.TryGetValue("SubjectUserName", out var subjectUser))
            secEvent.UserName = subjectUser?.ToString();
        if (data.TryGetValue("SubjectDomainName", out var subjectDomain))
            secEvent.UserDomain = subjectDomain?.ToString();
        if (data.TryGetValue("SubjectUserSid", out var subjectSid))
            secEvent.UserSid = subjectSid?.ToString();

        // Process fields - try multiple field name variations
        // Event 4688 uses: NewProcessName, NewProcessId, CommandLine, ParentProcessName
        // Sysmon Event 1 uses: Image, ProcessId, CommandLine, ParentImage
        // PowerShell uses: ScriptBlockText, Message (we don't extract Path for PowerShell)
        
        string? processPath = null;
        // Skip path extraction for PowerShell events - user doesn't want it
        if (!secEvent.Channel.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) &&
            !secEvent.Channel.Contains("Script", StringComparison.OrdinalIgnoreCase))
        {
            if (data.TryGetValue("NewProcessName", out var newProcName))
                processPath = newProcName?.ToString();
            else if (data.TryGetValue("Image", out var image))
                processPath = image?.ToString();
            else if (data.TryGetValue("ProcessName", out var procName))
                processPath = procName?.ToString();
            else if (data.TryGetValue("ProcessPath", out var procPath))
                processPath = procPath?.ToString();
            
            if (!string.IsNullOrEmpty(processPath))
            {
                secEvent.ProcessPath = processPath;
                secEvent.ProcessName = Path.GetFileName(processPath);
            }
        }
        
        // Process ID
        if (data.TryGetValue("NewProcessId", out var processId) && processId != null)
        {
            if (int.TryParse(processId.ToString()?.Replace("0x", ""), 
                System.Globalization.NumberStyles.HexNumber, null, out var pid))
                secEvent.ProcessId = pid;
        }
        else if (data.TryGetValue("ProcessId", out var procId) && procId != null)
        {
            if (int.TryParse(procId.ToString()?.Replace("0x", ""), 
                System.Globalization.NumberStyles.HexNumber, null, out var pid))
                secEvent.ProcessId = pid;
        }
        
        // Command Line - try multiple field names
        if (data.TryGetValue("CommandLine", out var cmdLine))
            secEvent.CommandLine = cmdLine?.ToString();
        else if (data.TryGetValue("Command", out var command))
            secEvent.CommandLine = command?.ToString();
        else if (data.TryGetValue("ScriptBlockText", out var scriptBlock))
            secEvent.CommandLine = scriptBlock?.ToString();
        else if (data.TryGetValue("Message", out var message) && 
                 (secEvent.Channel.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) ||
                  secEvent.Channel.Contains("Script", StringComparison.OrdinalIgnoreCase)))
        {
            // For PowerShell events, message often contains the command
            secEvent.CommandLine = message?.ToString();
        }
        
        // Parent Process
        if (data.TryGetValue("ParentProcessName", out var parentProcess))
            secEvent.ParentProcessName = parentProcess?.ToString();
        else if (data.TryGetValue("ParentImage", out var parentImage))
            secEvent.ParentProcessName = parentImage?.ToString();
        
        // Parent Process ID
        if (data.TryGetValue("ParentProcessId", out var parentProcId) && parentProcId != null)
        {
            if (int.TryParse(parentProcId.ToString()?.Replace("0x", ""), 
                System.Globalization.NumberStyles.HexNumber, null, out var ppid))
                secEvent.ParentProcessId = ppid;
        }
        
        // Parent Command Line
        if (data.TryGetValue("ParentCommandLine", out var parentCmdLine))
            secEvent.ParentCommandLine = parentCmdLine?.ToString();

        // Network fields
        if (data.TryGetValue("IpAddress", out var ip))
            secEvent.SourceIp = CleanIpAddress(ip?.ToString());
        if (data.TryGetValue("SourceAddress", out var srcIp))
            secEvent.SourceIp = CleanIpAddress(srcIp?.ToString());
        if (data.TryGetValue("DestAddress", out var destIp))
            secEvent.DestinationIp = CleanIpAddress(destIp?.ToString());
        if (data.TryGetValue("IpPort", out var port) && int.TryParse(port?.ToString(), out var portNum))
            secEvent.SourcePort = portNum;
        if (data.TryGetValue("SourcePort", out var srcPort) && int.TryParse(srcPort?.ToString(), out var srcPortNum))
            secEvent.SourcePort = srcPortNum;
        if (data.TryGetValue("DestPort", out var destPort) && int.TryParse(destPort?.ToString(), out var destPortNum))
            secEvent.DestinationPort = destPortNum;

        // Logon fields
        if (data.TryGetValue("LogonType", out var logonType) && int.TryParse(logonType?.ToString(), out var lt))
        {
            secEvent.LogonType = lt;
            secEvent.LogonTypeName = LogonTypes.GetName(lt);
        }
        if (data.TryGetValue("LogonId", out var logonId))
            secEvent.LogonId = logonId?.ToString();
        if (data.TryGetValue("AuthenticationPackageName", out var authPkg))
            secEvent.AuthenticationPackage = authPkg?.ToString();
        if (data.TryGetValue("WorkstationName", out var workstation))
            secEvent.WorkstationName = workstation?.ToString();

        // Object fields
        if (data.TryGetValue("ObjectName", out var objectName))
            secEvent.ObjectName = objectName?.ToString();
        if (data.TryGetValue("ObjectType", out var objectType))
            secEvent.ObjectType = objectType?.ToString();
        if (data.TryGetValue("AccessMask", out var accessMask))
            secEvent.AccessMask = accessMask?.ToString();

        // Service fields
        if (data.TryGetValue("ServiceName", out var serviceName))
            secEvent.ServiceName = serviceName?.ToString();
        if (data.TryGetValue("ServiceType", out var serviceType))
            secEvent.ServiceType = serviceType?.ToString();
        if (data.TryGetValue("ServiceStartType", out var startType))
            secEvent.ServiceStartType = startType?.ToString();
        if (data.TryGetValue("ServiceAccount", out var serviceAccount))
            secEvent.ServiceAccount = serviceAccount?.ToString();

        // AD fields
        if (data.TryGetValue("ObjectDN", out var dn))
            secEvent.ObjectDn = dn?.ToString();
        if (data.TryGetValue("ObjectGUID", out var guid))
            secEvent.ObjectGuid = guid?.ToString();
        if (data.TryGetValue("ObjectClass", out var objClass))
            secEvent.ObjectClass = objClass?.ToString();
        if (data.TryGetValue("AttributeName", out var attrName))
            secEvent.AttributeName = attrName?.ToString();
        if (data.TryGetValue("AttributeValue", out var attrValue))
            secEvent.AttributeValue = attrValue?.ToString();

        // Kerberos fields
        if (data.TryGetValue("TicketEncryptionType", out var encType))
            secEvent.TicketEncryptionType = encType?.ToString();
        if (data.TryGetValue("TicketOptions", out var ticketOpts))
            secEvent.TicketOptions = ticketOpts?.ToString();
        if (data.TryGetValue("ServiceName", out var svcNameKerb))
            secEvent.ServiceNameKerberos = svcNameKerb?.ToString();

        // Sysmon hashes
        if (data.TryGetValue("Hashes", out var hashes))
        {
            var hashStr = hashes?.ToString() ?? "";
            foreach (var hash in hashStr.Split(','))
            {
                var parts = hash.Split('=');
                if (parts.Length == 2)
                {
                    switch (parts[0].Trim().ToUpper())
                    {
                        case "MD5":
                            secEvent.FileHashMd5 = parts[1].Trim();
                            break;
                        case "SHA1":
                            secEvent.FileHashSha1 = parts[1].Trim();
                            break;
                        case "SHA256":
                            secEvent.FileHashSha256 = parts[1].Trim();
                            break;
                    }
                }
            }
        }

        // Status fields
        if (data.TryGetValue("Status", out var status))
            secEvent.Status = status?.ToString();
        if (data.TryGetValue("FailureReason", out var failReason))
            secEvent.FailureReason = failReason?.ToString();
    }

    private string? CleanIpAddress(string? ip)
    {
        if (string.IsNullOrEmpty(ip) || ip == "-" || ip == "::1" || ip == "127.0.0.1")
            return null;
        
        // Handle IPv6 mapped IPv4
        if (ip.StartsWith("::ffff:"))
            return ip.Substring(7);
            
        return ip;
    }

    private string GetLevelName(byte? level)
    {
        return level switch
        {
            0 => "LogAlways",
            1 => "Critical",
            2 => "Error",
            3 => "Warning",
            4 => "Information",
            5 => "Verbose",
            _ => "Unknown"
        };
    }
}


using System.Text.Json.Serialization;

namespace PhantomAgent.Models;

/// <summary>
/// Batch of events to send to the SIEM server
/// </summary>
public class EventBatch
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; set; } = string.Empty;

    [JsonPropertyName("agent_hostname")]
    public string AgentHostname { get; set; } = string.Empty;

    [JsonPropertyName("agent_ip")]
    public string? AgentIp { get; set; }

    [JsonPropertyName("batch_timestamp")]
    public DateTime BatchTimestamp { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("events")]
    public List<SecurityEvent> Events { get; set; } = new();
}

/// <summary>
/// Agent registration request
/// </summary>
public class AgentRegistration
{
    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = string.Empty;

    [JsonPropertyName("domain")]
    public string? Domain { get; set; }

    [JsonPropertyName("fqdn")]
    public string? Fqdn { get; set; }

    [JsonPropertyName("ip_address")]
    public string IpAddress { get; set; } = string.Empty;

    [JsonPropertyName("mac_address")]
    public string? MacAddress { get; set; }

    [JsonPropertyName("os_type")]
    public string OsType { get; set; } = string.Empty;

    [JsonPropertyName("os_version")]
    public string? OsVersion { get; set; }

    [JsonPropertyName("os_build")]
    public string? OsBuild { get; set; }

    [JsonPropertyName("architecture")]
    public string Architecture { get; set; } = "x64";

    [JsonPropertyName("is_domain_controller")]
    public bool IsDomainController { get; set; }

    [JsonPropertyName("server_role")]
    public string ServerRole { get; set; } = "WORKSTATION";

    [JsonPropertyName("agent_version")]
    public string AgentVersion { get; set; } = "1.0.0";
    
    [JsonPropertyName("enabled_channels")]
    public List<string>? EnabledChannels { get; set; }
}

/// <summary>
/// Heartbeat request
/// </summary>
public class HeartbeatRequest
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; set; } = string.Empty;

    [JsonPropertyName("cpu_percent")]
    public float CpuPercent { get; set; }

    [JsonPropertyName("memory_percent")]
    public float MemoryPercent { get; set; }

    [JsonPropertyName("disk_percent")]
    public float DiskPercent { get; set; }

    [JsonPropertyName("events_in_queue")]
    public int EventsInQueue { get; set; }

    [JsonPropertyName("events_sent")]
    public int EventsSent { get; set; }

    [JsonPropertyName("errors_count")]
    public int ErrorsCount { get; set; }

    [JsonPropertyName("is_healthy")]
    public bool IsHealthy { get; set; } = true;

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}


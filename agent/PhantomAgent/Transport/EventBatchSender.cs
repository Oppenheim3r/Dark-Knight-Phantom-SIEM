using System.Collections.Concurrent;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using PhantomAgent.Configuration;
using PhantomAgent.Models;
using Serilog;

namespace PhantomAgent.Transport;

/// <summary>
/// Handles batching and sending events to the SIEM server
/// </summary>
public class EventBatchSender
{
    private readonly AgentConfig _config;
    private readonly SiemHttpClient _client;
    private readonly ConcurrentQueue<SecurityEvent> _eventQueue = new();
    private readonly string _hostname;
    private readonly string? _ipAddress;
    
    public int QueuedEvents => _eventQueue.Count;
    public int TotalEventsSent { get; private set; }
    public int ErrorCount { get; private set; }

    public EventBatchSender(AgentConfig config, SiemHttpClient client)
    {
        _config = config;
        _client = client;
        _hostname = Environment.MachineName;
        _ipAddress = GetLocalIpAddress();
    }

    /// <summary>
    /// Queue events for sending
    /// </summary>
    public void QueueEvents(IEnumerable<SecurityEvent> events)
    {
        foreach (var evt in events)
        {
            _eventQueue.Enqueue(evt);
        }
    }

    /// <summary>
    /// Send queued events in batches
    /// </summary>
    public async Task SendQueuedEventsAsync()
    {
        while (_eventQueue.Count >= _config.BatchSize || 
               (_eventQueue.Count > 0 && _eventQueue.Count < _config.BatchSize))
        {
            var batch = new List<SecurityEvent>();
            
            while (batch.Count < _config.BatchSize && _eventQueue.TryDequeue(out var evt))
            {
                batch.Add(evt);
            }

            if (batch.Count == 0) break;

            var eventBatch = new EventBatch
            {
                AgentId = _config.AgentId,
                AgentHostname = _hostname,
                AgentIp = _ipAddress,
                BatchTimestamp = DateTime.UtcNow,
                Events = batch
            };

            var success = await SendBatchWithRetryAsync(eventBatch);
            
            if (success)
            {
                TotalEventsSent += batch.Count;
                Log.Information("Sent {Count} events to SIEM server", batch.Count);
            }
            else
            {
                // Re-queue failed events
                foreach (var evt in batch)
                {
                    _eventQueue.Enqueue(evt);
                }
                ErrorCount++;
                break; // Stop trying, wait for next cycle
            }
        }
    }

    /// <summary>
    /// Send batch with retry logic
    /// </summary>
    private async Task<bool> SendBatchWithRetryAsync(EventBatch batch, int maxRetries = 3)
    {
        for (int i = 0; i < maxRetries; i++)
        {
            try
            {
                var response = await _client.SendEventsAsync(batch);
                
                if (response != null && response.Status == "success")
                {
                    return true;
                }
            }
            catch (HttpRequestException ex)
            {
                Log.Warning("HTTP error sending events (attempt {Attempt}): {Error}", i + 1, ex.Message);
            }
            catch (TaskCanceledException)
            {
                Log.Warning("Request timeout sending events (attempt {Attempt})", i + 1);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error sending events (attempt {Attempt})", i + 1);
            }

            if (i < maxRetries - 1)
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, i))); // Exponential backoff
            }
        }

        return false;
    }

    /// <summary>
    /// Get local IP address
    /// </summary>
    private string? GetLocalIpAddress()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return ip.Address.ToString();
                        }
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }

        return null;
    }
}




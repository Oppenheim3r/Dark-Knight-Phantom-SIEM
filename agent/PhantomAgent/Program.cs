using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PhantomAgent.Configuration;
using PhantomAgent.Services;
using PhantomAgent.Transport;
using PhantomAgent.Collectors;
using Serilog;

namespace PhantomAgent;

/// <summary>
/// Dark Knight Phantom SIEM Agent
/// Windows Event Log Collection Agent
/// </summary>
public class Program
{
    public static async Task Main(string[] args)
    {
        // Configure Serilog
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
            .WriteTo.File(
                path: "logs/phantom-agent-.log",
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
            .CreateLogger();

        try
        {
            Log.Information("==============================================");
            Log.Information("   Dark Knight Phantom SIEM Agent v1.0.0");
            Log.Information("   Windows Event Log Collection Service");
            Log.Information("==============================================");

            var builder = Host.CreateApplicationBuilder(args);

            // Load configuration
            var config = AgentConfig.Load();
            builder.Services.AddSingleton(config);

            // Add HTTP client for SIEM server communication
            builder.Services.AddHttpClient<SiemHttpClient>(client =>
            {
                client.BaseAddress = new Uri(config.ServerUrl);
                client.DefaultRequestHeaders.Add("X-Agent-ID", config.AgentId);
                client.Timeout = TimeSpan.FromSeconds(30);
            });

            // Add services
            builder.Services.AddSingleton<EventBatchSender>();
            builder.Services.AddSingleton<WindowsEventCollector>();
            builder.Services.AddHostedService<AgentService>();
            builder.Services.AddHostedService<HeartbeatService>();

            // Add Serilog
            builder.Services.AddSerilog();

            // Configure as Windows Service
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "PhantomAgent";
            });

            var host = builder.Build();
            await host.RunAsync();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Agent terminated unexpectedly");
        }
        finally
        {
            await Log.CloseAndFlushAsync();
        }
    }
}




# 🦇 Dark Knight Phantom SIEM

A Security Information and Event Management system for Windows environments.

## Overview

Dark Knight Phantom SIEM is a comprehensive security monitoring solution designed for Windows environments. It consists of a lightweight C# agent for event collection and a powerful Django backend for data ingestion, storage, querying, and alerting.

## Features

- ✅ **Windows Event Log Collection** - Supports 36+ event channels
- ✅ **Active Directory Support** - Directory Service, DFS Replication, DNS Server, LDAP, Group Policy logs
- ✅ **C# Agent** - Lightweight Windows service for event collection
- ✅ **16 Built-in Detection Rules** - MITRE ATT&CK mapped threat detection
- ✅ **Behavioral Analysis Engine** - Entity tracking and correlation
- ✅ **PQL Query Language** - Custom query language for event analysis
- ✅ **REST API** - Full-featured API for integration
- ✅ **Dark Theme Web UI** - Modern, responsive dashboard
- ✅ **Sysmon Integration** - Advanced process and network monitoring
- ✅ **PowerShell Logging** - Comprehensive PowerShell event collection

## Quick Start

### Prerequisites

- Python 3.13+
- PostgreSQL (database: `dark_knight_phantom`, user: `root`, password: `admin`)
- .NET 8.0 SDK (for agent compilation)

### 1. Database Setup

```sql
CREATE DATABASE dark_knight_phantom;
CREATE USER root WITH PASSWORD 'admin';
GRANT ALL PRIVILEGES ON DATABASE dark_knight_phantom TO root;
```

### 2. Backend Setup

```cmd
cd backend
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

### 3. Install Detection Rules

```cmd
cd backend
python manage.py shell -c "from apps.detection.builtin_rules import install_builtin_rules; install_builtin_rules()"
```

### 4. Build and Configure Agent

```cmd
cd agent
build_agent.bat
```

Edit `agent/PhantomAgent/bin/Release/net8.0-windows/config.json`:
```json
{
  "agent_id": "",
  "server_url": "http://YOUR_SERVER_IP:8000/api/v1/",
  "collection_interval_seconds": 30,
  "batch_size": 100
}
```

### 5. Enable PowerShell Logging

Run as Administrator:
```powershell
.\enable_powershell_logging.ps1
```

### 6. Install Sysmon (Optional)

Run as Administrator:
```cmd
cd sysmon
install_sysmon.bat
```

### 7. Start Agent

```cmd
agent\PhantomAgent\bin\Release\net8.0-windows\PhantomAgent.exe
```

### 8. Access Dashboard

Open: http://localhost:8000/events/

## Documentation

See `DARK_KNIGHT_PHANTOM_SIEM_DOCUMENTATION.md` for complete documentation, including:
- All supported event channels and IDs
- PQL query language syntax and examples
- Detection rules and MITRE ATT&CK mapping
- API endpoints
- Configuration guide

## Project Structure

```
Dark-Knight-Phantom-SIEM-Release/
├── backend/              # Django backend
│   ├── apps/            # Django applications
│   ├── templates/       # HTML templates
│   ├── static/         # CSS/JS assets
│   └── manage.py
├── agent/               # C# agent
│   └── PhantomAgent/   # Agent source code
├── emulation/           # Threat emulation scripts
├── sysmon/              # Sysmon configuration and installer
└── docs/                # Documentation files
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/v1/agents/` | Agent management |
| `/api/v1/events/` | Event storage and retrieval |
| `/api/v1/detection/rules/` | Detection rules management |
| `/api/v1/detection/alerts/` | Security alerts |
| `/api/v1/query/execute/` | PQL query execution |

## PQL Query Examples

```pql
# Search for failed logons
SEARCH events WHERE event_id = 4625 LIMIT 100

# Find PowerShell activity
SEARCH events WHERE message CONTAINS powershell AND timestamp >= 24h

# Aggregate by source IP
AGGREGATE events BY source_ip COUNT WHERE event_id = 4625 WITHIN 1h

# Hunt for critical events
HUNT events WHERE severity = CRITICAL LIMIT 50
```

## Detection Rules

The system includes 16 built-in detection rules covering:
- Authentication attacks (brute force, password spray)
- Privilege escalation
- Lateral movement
- Persistence mechanisms
- Defense evasion
- Service installations
- Suspicious PowerShell activity

All rules are mapped to MITRE ATT&CK techniques.

## Testing

Run emulation scripts to test detection:
```powershell
cd emulation
.\run_all_emulations.ps1
```

## License

MIT License - See LICENSE file for details.

**Note:** This software is intended for educational and lab use only. Use at your own risk.

## Contributing

Contributions are welcome! Please ensure all code follows the existing style and includes appropriate tests.

## Support

For issues and questions, please refer to:
- `AGENT_TROUBLESHOOTING.md` - Agent troubleshooting guide
- `AGENT_CONFIG_README.md` - Agent configuration guide
- `DARK_KNIGHT_PHANTOM_SIEM_DOCUMENTATION.md` - Complete documentation

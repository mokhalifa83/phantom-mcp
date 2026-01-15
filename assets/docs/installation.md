# 👻 PHANTOM MCP - Installation Guide

## Prerequisites

Before installing PHANTOM MCP, ensure you have the following:

### Required
- **Python 3.10 or higher**
- **pip** package manager
- **Git** (for cloning the repository)

### External Tools
- **nmap** - Network exploration tool
  - **Linux**: `sudo apt-get install nmap`
  - **macOS**: `brew install nmap`
  - **Windows**: Download from [nmap.org](https://nmap.org/download.html)

### Optional
- **Redis** - For session management
  - **Linux**: `sudo apt-get install redis-server`
  - **macOS**: `brew install redis`
  - **Windows**: Redis on Windows is available through WSL

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/phantom-mcp.git
cd phantom-mcp
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install core dependencies
pip install -r requirements.txt

# Or install with development tools
pip install -e ".[dev]"

# Or install with all optional features
pip install -e ".[full]"
```

### 4. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your settings
nano .env  # or use your preferred editor
```

Required environment variables:
```env
ANTHROPIC_API_KEY=your_claude_api_key_here
```

### 5. Create Required Directories

```bash
mkdir -p logs reports wordlists
```

### 6. Test Installation

```bash
# Run tests
pytest tests/

# Or test the server
python -m phantom.server --help
```

## Configuration

### Main Configuration

Edit `configs/phantom.yaml` to customize PHANTOM behavior:

```yaml
security:
  safe_mode: true
  require_confirmation: true

ai:
  enable_ai: true
  model: "claude-3-5-sonnet-20241022"

logging:
  level: "INFO"
  file_path: "logs/phantom.log"
```

### Tool Configuration

Edit `configs/tools.yaml` to enable/disable specific tools:

```yaml
tools:
  auto_exploit:
    enabled: false  # Keep disabled unless authorized
```

## Claude Desktop Integration

To use PHANTOM with Claude Desktop, add to your `claude_desktop_config.json`:

**Location:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

**Configuration:**
```json
{
  "mcpServers": {
    "phantom": {
      "command": "python",
      "args": ["-m", "phantom.server"],
      "cwd": "/path/to/phantom-mcp",
      "env": {
        "ANTHROPIC_API_KEY": "your_key_here",
        "PHANTOM_SAFE_MODE": "true"
      }
    }
  }
}
```

## Verification

After installation, verify everything works:

```bash
# Activate virtual environment
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Run server in test mode
python -m phantom.server
```

You should see the PHANTOM logo and initialization messages.

## Troubleshooting

### nmap not found
- Ensure nmap is installed and in PATH
- Verify with: `nmap --version`

### Python version error
- Check Python version: `python --version`
- Ensure you're using Python 3.10+

### API Key not working
- Verify ANTHROPIC_API_KEY is set correctly
- Check .env file has no extra spaces

### Import errors
- Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`

## Next Steps

- Read the [Usage Guide](usage.md)
- Review the [Legal Guidelines](legal.md)
- Configure your first scan

## Support

- 📧 Email: support@phantom-mcp.dev
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/phantom-mcp/issues)
- 💬 Discord: [Join our server](https://discord.gg/phantom)

---

**👻 Strike from the shadows. Test with purpose.**

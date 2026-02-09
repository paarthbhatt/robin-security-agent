# Integrating ROBIN with OpenClaw 🦞

ROBIN is designed to work seamlessly as a high-intelligence specialist within the [OpenClaw](https://openclaw.ai) ecosystem. By integrating ROBIN, your primary OpenClaw agent (like ALFRED) can delegate complex security reconnaissance tasks to a dedicated autonomous sidekick.

## 🛠 Integration Steps

### 1. Add to your OpenClaw Configuration
Open your `openclaw.json` (usually in `~/.openclaw/openclaw.json`) and add ROBIN to the `agents.list` array:

```json
{
  "agents": {
    "list": [
      {
        "id": "robin",
        "name": "ROBIN",
        "workspace": "/path/to/cloned/robin-security-agent",
        "model": "google-antigravity/claude-sonnet-4-5-thinking"
      }
    ]
  }
}
```

### 2. Configure Task-Aware Routing
To make your main agent automatically use ROBIN for security tasks, update your `task-router` skill or system prompt with the following logic:

**Classification Rubric:**
- **IF** task involves: `GitHub scanning`, `CVE lookup`, `vulnerability analysis`, or `security reconnaissance`.
- **THEN** delegate to agent `robin` using the `sessions_spawn` tool.

### 3. Usage via CLI or Chat
Once registered, you can summon ROBIN directly from your primary chat (WhatsApp/Telegram/Discord) or via the CLI:

**Example Command:**
> "Hey Alfred, spawn Robin to scan the repository `paarthbhatt/Cybersecurity-MCP-Servers` and check for any leaked secrets."

**Manual Execution:**
```bash
openclaw agent --agentId robin --message "Analyze CVE-2024-12345"
```

## 🔌 Tool Integration
ROBIN uses the `gh` CLI for its GitHub operations. Ensure your OpenClaw environment has the GitHub CLI installed and authenticated (`gh auth login`) so ROBIN can leverage your credentials for reconnaissance.

## 🚀 Advanced: Automated Security Sprints
You can schedule ROBIN to perform periodic security audits of your repos using OpenClaw's `cron` system:

```bash
openclaw cron add --name "Weekly Security Audit" --schedule "cron:0 0 * * 0" --payload "agentTurn:robin:Perform full recon on my-main-repo"
```

---
*Operational Security Note: ROBIN is built for reconnaissance. Always review its findings before taking remediation actions.*

# ROBIN 🤖

ROBIN (Reconnaissance & Operations Bot for Intelligence Networks) is an autonomous security research agent that thinks, plans, and executes tactical reconnaissance. Built on the foundation of the Dexter architecture, ROBIN is designed to be the ultimate sidekick for cybersecurity professionals.

## 👋 Overview

ROBIN takes complex security objectives and turns them into clear, step-by-step reconnaissance plans. It runs those tasks using live vulnerability data, GitHub analysis, and technical advisories.

**Key Capabilities:**
- **Tactical Task Planning**: Automatically decomposes security goals into structured research steps.
- **GitHub Reconnaissance**: Direct integration with the `gh` CLI for deep repo analysis and secret discovery.
- **Vulnerability Analysis**: Real-time lookup of CVE data via the NVD database.
- **Autonomous Execution**: Selects and executes the right tools to gather technical intelligence.
- **Self-Validation**: Checks its own logic and iterates until threat assessments are complete.

## ✅ Prerequisites

- [Bun](https://bun.com) runtime (v1.0 or higher)
- [GitHub CLI (gh)](https://cli.github.com/) authenticated.
- OpenAI or Anthropic API key.

## 💻 How to Install

1. Clone the repository:
```bash
git clone https://github.com/paarthbhatt/robin-security-agent.git
cd robin-security-agent
```

2. Install dependencies with Bun:
```bash
bun install
```

3. Set up your environment variables:
```bash
cp env.example .env
# Add your API keys to .env
```

## 🚀 How to Run

Run ROBIN in interactive mode:
```bash
bun start
```

---
*Created by Parth Bhatt. Inspired by Dexter.*

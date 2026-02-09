import { buildToolDescriptions } from '../tools/registry.js';
import { buildSkillMetadataSection, discoverSkills } from '../skills/index.js';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Returns the current date formatted for prompts.
 */
export function getCurrentDate(): string {
  const options: Intl.DateTimeFormatOptions = {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  };
  return new Date().toLocaleDateString('en-US', options);
}

/**
 * Build the skills section for the system prompt.
 * Only includes skill metadata if skills are available.
 */
function buildSkillsSection(): string {
  const skills = discoverSkills();
  
  if (skills.length === 0) {
    return '';
  }

  const skillList = buildSkillMetadataSection();
  
  return `## Available Skills

${skillList}

## Skill Usage Policy

- Check if available skills can help complete the task more effectively
- When a skill is relevant, invoke it IMMEDIATELY as your first action
- Skills provide specialized workflows for complex security tasks (e.g., Threat Modeling)
- Do not invoke a skill that has already been invoked for the current query`;
}

// ============================================================================
// System Prompt
// ============================================================================

/**
 * Build the system prompt for the agent.
 * @param model - The model name (used to get appropriate tool descriptions)
 */
export function buildSystemPrompt(model: string): string {
  const toolDescriptions = buildToolDescriptions(model);

  return `You are ROBIN (Reconnaissance & Operations Bot for Intelligence Networks), a specialized security research agent and sidekick to BATMAN.

Current date: ${getCurrentDate()}

Your output is displayed on a command line interface. Keep responses short, tactical, and highly actionable.

## Available Tools

${toolDescriptions}

## Tool Usage Policy

- Only use tools when the query actually requires external data or reconnaissance.
- ALWAYS prefer github_recon for any repository-specific analysis.
- Use web_search or browser for finding CVE details, exploit PoCs, or security advisories.
- For factual questions about software vulnerabilities, use tools to verify the latest patches and CVE IDs.
- Do NOT leak sensitive authorization data or keys in your terminal output.

${buildSkillsSection()}

## Behavior

- Prioritize accuracy over validation. If a system looks secure, say so; if it looks compromised, provide evidence.
- Use a sharp, tactical, and slightly informal tone (sidekick persona).
- For reconnaissance tasks, be thorough but quiet. 
- Never ask users to provide raw data they don't have access to. 
- If reconnaissance is incomplete, report the exact point of failure and recommend the next tactical step.

## Response Format

- Keep responses brief and direct. Lead with the "Threat Level" or "Vulnerability Found".
- For non-comparative information, prefer plain text or simple bullet points.
- Do not use markdown headers or *italics* - use **bold** sparingly for emphasis.

## Tables (for vulnerability lists/data)

Use markdown tables. They will be rendered as formatted box tables.

STRICT FORMAT - each row must:
- Start with | and end with |
- Have no trailing spaces after the final |
- Use |---| separator

| CVE ID       | Severity | Status     |
|--------------|----------|------------|
| CVE-2024-123 | Critical | Unpatched  |

Keep tables compact. Headers: 1-3 words max.`;
}

// ============================================================================
// User Prompts
// ============================================================================

/**
 * Build user prompt for agent iteration with full tool results.
 * Anthropic-style: full results in context for accurate decision-making.
 * Context clearing happens at threshold, not inline summarization.
 * 
 * @param originalQuery - The user's original query
 * @param fullToolResults - Formatted full tool results (or placeholder for cleared)
 * @param toolUsageStatus - Optional tool usage status for graceful exit mechanism
 */
export function buildIterationPrompt(
  originalQuery: string,
  fullToolResults: string,
  toolUsageStatus?: string | null
): string {
  let prompt = `Query: ${originalQuery}`;

  if (fullToolResults.trim()) {
    prompt += `

Data retrieved from tool calls:
${fullToolResults}`;
  }

  // Add tool usage status if available (graceful exit mechanism)
  if (toolUsageStatus) {
    prompt += `\n\n${toolUsageStatus}`;
  }

  prompt += `

Continue working toward answering the query. If you have gathered actual content (not just links or titles), you may respond. For browser tasks: seeing a link is NOT the same as reading it - you must click through (using the ref) OR navigate to its visible /url value. NEVER guess at URLs - use ONLY URLs visible in snapshots.`;

  return prompt;
}

// ============================================================================
// Final Answer Generation
// ============================================================================

/**
 * Build the prompt for final answer generation with full context data.
 * This is used after context compaction - full data is loaded from disk for the final answer.
 */
export function buildFinalAnswerPrompt(
  originalQuery: string,
  fullContextData: string
): string {
  return `Query: ${originalQuery}

Data retrieved from your tool calls:
${fullContextData}

Answer the user's query using this data. Do not ask the user to provide additional data, paste values, or reference JSON/API internals. If data is incomplete, answer with what you have.`;
}


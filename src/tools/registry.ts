import { StructuredToolInterface } from '@langchain/core/tools';
import { githubRecon } from './security/github-recon.js';
import { cveLookup } from './security/cve-lookup.js';
import { dependencyAudit } from './security/dependency-audit.js';
import { staticAnalysis } from './security/static-analysis.js';
import { exaSearch, tavilySearch } from './search/index.js';
import { skillTool, SKILL_TOOL_DESCRIPTION } from './skill.js';
import { browserTool } from './browser/index.js';
import { WEB_SEARCH_DESCRIPTION, BROWSER_DESCRIPTION } from './descriptions/index.js';
import { discoverSkills } from '../skills/index.js';

export const GITHUB_RECON_DESCRIPTION = `
Search and analyze GitHub repositories for security vulnerabilities, secrets, or architectural flaws. 
Use this to:
1. List files in a repository to understand its structure.
2. Search for common patterns (e.g., 'password', 'apiKey', 'eval(') within the code.
3. Read specific files to perform deep manual audit.
`;

export const CVE_LOOKUP_DESCRIPTION = `
Lookup vulnerability details using a CVE ID. 
Use this when you have a specific CVE identifier and need to understand the threat level, technical details, and potential patches.
`;

export const DEPENDENCY_AUDIT_DESCRIPTION = `
Audit project dependencies for known vulnerabilities using npm/yarn/bun audit.
Use this to check for vulnerable packages in the project's supply chain.
`;

export const STATIC_ANALYSIS_DESCRIPTION = `
Perform static code analysis to find common security anti-patterns like hardcoded secrets, eval() usage, or dangerous HTML rendering.
`;

/**
 * A registered tool with its rich description for system prompt injection.
 */
export interface RegisteredTool {
  /** Tool name (must match the tool's name property) */
  name: string;
  /** The actual tool instance */
  tool: StructuredToolInterface;
  /** Rich description for system prompt (includes when to use, when not to use, etc.) */
  description: string;
}

/**
 * Get all registered tools with their descriptions.
 * Conditionally includes tools based on environment configuration.
 *
 * @param model - The model name (needed for tools that require model-specific configuration)
 * @returns Array of registered tools
 */
export function getToolRegistry(model: string): RegisteredTool[] {
  const tools: RegisteredTool[] = [
    {
      name: 'github_recon',
      tool: githubRecon,
      description: GITHUB_RECON_DESCRIPTION,
    },
    {
      name: 'cve_lookup',
      tool: cveLookup,
      description: CVE_LOOKUP_DESCRIPTION,
    },
    {
      name: 'dependency_audit',
      tool: dependencyAudit,
      description: DEPENDENCY_AUDIT_DESCRIPTION,
    },
    {
      name: 'static_analysis',
      tool: staticAnalysis,
      description: STATIC_ANALYSIS_DESCRIPTION,
    },
    {
      name: 'browser',
      tool: browserTool,
      description: BROWSER_DESCRIPTION,
    },
  ];

  // Include web_search if Exa or Tavily API key is configured (Exa preferred)
  if (process.env.EXASEARCH_API_KEY) {
    tools.push({
      name: 'web_search',
      tool: exaSearch,
      description: WEB_SEARCH_DESCRIPTION,
    });
  } else if (process.env.TAVILY_API_KEY) {
    tools.push({
      name: 'web_search',
      tool: tavilySearch,
      description: WEB_SEARCH_DESCRIPTION,
    });
  }

  // Include skill tool if any skills are available
  const availableSkills = discoverSkills();
  if (availableSkills.length > 0) {
    tools.push({
      name: 'skill',
      tool: skillTool,
      description: SKILL_TOOL_DESCRIPTION,
    });
  }

  return tools;
}

/**
 * Get just the tool instances for binding to the LLM.
 *
 * @param model - The model name
 * @returns Array of tool instances
 */
export function getTools(model: string): StructuredToolInterface[] {
  return getToolRegistry(model).map((t) => t.tool);
}

/**
 * Build the tool descriptions section for the system prompt.
 * Formats each tool's rich description with a header.
 *
 * @param model - The model name
 * @returns Formatted string with all tool descriptions
 */
export function buildToolDescriptions(model: string): string {
  return getToolRegistry(model)
    .map((t) => `### ${t.name}\n\n${t.description}`)
    .join('\n\n');
}

/**
 * Generate a deterministic human-readable description of a tool call.
 * Used for context compaction during the agent loop.
 * 
 * Examples:
 * - "AAPL income statements (annual) - 5 periods"
 * - '"bitcoin price" tavily search'
 */
export function getToolDescription(toolName: string, args: Record<string, unknown>): string {
  const parts: string[] = [];
  const usedKeys = new Set<string>();

  // Add repo if present (common for security tools)
  if (args.repo) {
    parts.push(`Repo: ${args.repo}`);
    usedKeys.add('repo');
  }

  // Add CVE ID if present
  if (args.cveId) {
    parts.push(String(args.cveId).toUpperCase());
    usedKeys.add('cveId');
  }

  // Add search query if present
  if (args.query) {
    parts.push(`"${args.query}"`);
    usedKeys.add('query');
  }

  // Format tool name
  const formattedToolName = toolName
    .replace(/^github_/, '')
    .replace(/^cve_/, '')
    .replace(/_/g, ' ');
  parts.push(formattedToolName);

  // Add path qualifier if present
  if (args.path || args.repoPath) {
    parts.push(`at ${args.path || args.repoPath}`);
    usedKeys.add('path');
    usedKeys.add('repoPath');
  }

  // Append any remaining args not explicitly handled
  const remainingArgs = Object.entries(args)
    .filter(([key]) => !usedKeys.has(key))
    .map(([key, value]) => `${key}=${value}`);

  if (remainingArgs.length > 0) {
    parts.push(`[${remainingArgs.join(', ')}]`);
  }

  return parts.join(' ');
}

import { DynamicStructuredTool } from '@langchain/core/tools';
import { z } from 'zod';
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

export const githubRecon = new DynamicStructuredTool({
  name: 'github_recon',
  description: 'Perform security reconnaissance on a GitHub repository. Can list files, search for secrets, or read code using the gh CLI.',
  schema: z.object({
    repo: z.string().describe('The full repository name (e.g., owner/repo)'),
    action: z.enum(['list_files', 'search_code', 'read_file']).describe('The action to perform'),
    query: z.string().optional().describe('The search query or filename to read'),
  }),
  func: async ({ repo, action, query }) => {
    try {
      let command = '';
      if (action === 'list_files') {
        command = `gh api repos/${repo}/contents`;
      } else if (action === 'search_code') {
        command = `gh api "search/code?q=${encodeURIComponent(query || '')}+repo:${repo}"`;
      } else if (action === 'read_file') {
        command = `gh api repos/${repo}/contents/${query}`;
      }

      const { stdout, stderr } = await execPromise(command);
      if (stderr && !stdout) return `Error: ${stderr}`;
      
      const data = JSON.parse(stdout);
      if (action === 'read_file' && data.content) {
        return Buffer.from(data.content, 'base64').toString('utf8');
      }
      
      return JSON.stringify(data, null, 2);
    } catch (error: any) {
      return `Error performing recon: ${error.message}`;
    }
  },
});

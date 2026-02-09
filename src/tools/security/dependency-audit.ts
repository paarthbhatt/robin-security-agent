import { DynamicStructuredTool } from '@langchain/core/tools';
import { z } from 'zod';
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

export const dependencyAudit = new DynamicStructuredTool({
  name: 'dependency_audit',
  description: 'Audit a repository for vulnerable dependencies using npm audit or yarn audit.',
  schema: z.object({
    repoPath: z.string().describe('The local path to the repository to audit'),
    manager: z.enum(['npm', 'yarn', 'bun']).describe('The package manager to use'),
  }),
  func: async ({ repoPath, manager }) => {
    try {
      let command = '';
      if (manager === 'npm') {
        command = `cd ${repoPath} && npm audit --json`;
      } else if (manager === 'yarn') {
        command = `cd ${repoPath} && yarn audit --json`;
      } else if (manager === 'bun') {
        // Bun doesn't have a direct 'audit' yet that matches npm's JSON output, 
        // but we can check the lockfile or use npm audit on the package.json.
        command = `cd ${repoPath} && npm audit --json`; 
      }

      const { stdout, stderr } = await execPromise(command);
      // npm audit returns non-zero exit code if vulnerabilities are found, 
      // so we handle that in the catch block or by checking stdout.
      return stdout || stderr;
    } catch (error: any) {
      if (error.stdout) return error.stdout; // Return the audit report even if exit code is non-zero
      return `Error performing audit: ${error.message}`;
    }
  },
});

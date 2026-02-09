import { DynamicStructuredTool } from '@langchain/core/tools';
import { z } from 'zod';
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

export const staticAnalysis = new DynamicStructuredTool({
  name: 'static_analysis',
  description: 'Perform lightweight static analysis on a file or directory for common security anti-patterns.',
  schema: z.object({
    path: z.string().describe('The local path to the file or directory to analyze'),
  }),
  func: async ({ path }) => {
    try {
      // Searching for dangerous patterns: eval, dangerouslySetInnerHTML, hardcoded keys, etc.
      const patterns = [
        { name: 'eval()', regex: 'eval\\(' },
        { name: 'Inner HTML', regex: 'dangerouslySetInnerHTML' },
        { name: 'Hardcoded Secret?', regex: '(password|apiKey|secret|token)\\s*[:=]\\s*["\'][^"\']{8,}' },
        { name: 'Shell Execution', regex: 'child_process\\.exec' }
      ];

      let report = `### Static Analysis Report: ${path}\n\n`;
      
      for (const pattern of patterns) {
        const cmd = `grep -rnE "${pattern.regex}" ${path} | head -n 10`;
        try {
          const { stdout } = await execPromise(cmd);
          if (stdout) {
            report += `#### Found: ${pattern.name}\n\`\`\`\n${stdout}\n\`\`\`\n`;
          }
        } catch (e) {
          // Grep returns 1 if no matches found
        }
      }

      return report === `### Static Analysis Report: ${path}\n\n` ? "No immediate security anti-patterns detected." : report;
    } catch (error: any) {
      return `Error performing analysis: ${error.message}`;
    }
  },
});

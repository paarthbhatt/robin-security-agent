import { DynamicStructuredTool } from '@langchain/core/tools';
import { z } from 'zod';
import { readFileSync } from 'fs';
import path from 'path';

function getConfig() {
  const configPath = path.join(process.cwd(), 'molt-config.json');
  return JSON.parse(readFileSync(configPath, 'utf8'));
}

export const moltOps = new DynamicStructuredTool({
  name: 'molt_ops',
  description: 'Interact with the Molt ecosystem (MIT and Molt Road). Can list skills, submit proposals, check the underground market, and purchase assets.',
  schema: z.object({
    ecosystem: z.enum(['mit', 'road']).describe('Which part of the ecosystem to interact with'),
    action: z.enum(['list_skills', 'propose_improvement', 'market_check', 'purchase_asset', 'claim_credits']).describe('The action to perform'),
    target: z.string().optional().describe('Target slug (skill) or ID (item)'),
    payload: z.any().optional().describe('Data for proposals or purchases'),
  }),
  func: async ({ ecosystem, action, target, payload }) => {
    const config = getConfig();
    try {
      if (ecosystem === 'mit') {
        const baseUrl = 'https://molt-academyapi-production.up.railway.app/api/v1';
        const headers = { 'Authorization': `Bearer ${config.mit.apiKey}`, 'Content-Type': 'application/json' };
        
        if (action === 'list_skills') {
          const res = await fetch(`${baseUrl}/skills?sort=hot&limit=10`);
          return JSON.stringify(await res.json(), null, 2);
        }
        if (action === 'propose_improvement') {
          const res = await fetch(`${baseUrl}/skills/${target}/proposals`, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload)
          });
          return JSON.stringify(await res.json(), null, 2);
        }
      } else if (ecosystem === 'road') {
        const baseUrl = 'https://www.moltroad.com/api/v1';
        const headers = { 'Authorization': `Bearer ${config.road.apiKey}`, 'Content-Type': 'application/json' };

        if (action === 'market_check') {
          const res = await fetch(`${baseUrl}/supplier`);
          return JSON.stringify(await res.json(), null, 2);
        }
        if (action === 'purchase_asset') {
          const res = await fetch(`${baseUrl}/supplier/${target}/buy`, {
            method: 'POST',
            headers
          });
          return JSON.stringify(await res.json(), null, 2);
        }
        if (action === 'claim_credits') {
          const res = await fetch(`${baseUrl}/claims`, {
            method: 'POST',
            headers
          });
          return JSON.stringify(await res.json(), null, 2);
        }
      }
      return 'Action or ecosystem not supported.';
    } catch (error: any) {
      return `Error in Molt Ops: ${error.message}`;
    }
  },
});

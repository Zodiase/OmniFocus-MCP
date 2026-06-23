import { describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync } from 'crypto';
import {
  createDangerousGrantToken,
  createExactDangerousGrantClaims,
  resetDangerousGrantReplayCache,
} from './dangerousGrant.js';
import {
  blockedToolResult,
  dangerousGrantRequiredResult,
  dangerousDryRunResult,
  getOmniFocusMcpMode,
  getToolAccessLevel,
  guardToolHandler,
  isDangerousDryRunEnabled,
  isToolAllowed,
} from './policy.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

describe('OmniFocus MCP safety policy', () => {
  describe('getOmniFocusMcpMode', () => {
    it('defaults to readonly', () => {
      expect(getOmniFocusMcpMode({})).toBe('readonly');
    });

    it('accepts write and dangerous modes', () => {
      expect(getOmniFocusMcpMode({ OMNIFOCUS_MCP_MODE: 'write' })).toBe('write');
      expect(getOmniFocusMcpMode({ OMNIFOCUS_MCP_MODE: 'dangerous' })).toBe('dangerous');
    });

    it('falls back to readonly for unknown modes', () => {
      expect(getOmniFocusMcpMode({ OMNIFOCUS_MCP_MODE: 'oops' })).toBe('readonly');
    });
  });

  describe('tool access levels', () => {
    it('classifies query tools as read operations', () => {
      expect(getToolAccessLevel('query_omnifocus')).toBe('read');
      expect(getToolAccessLevel('dump_database')).toBe('read');
      expect(getToolAccessLevel('list_tags')).toBe('read');
    });

    it('classifies ordinary create and edit tools as writes', () => {
      expect(getToolAccessLevel('add_omnifocus_task')).toBe('write');
      expect(getToolAccessLevel('create_tag')).toBe('write');
      expect(getToolAccessLevel('edit_item', { newName: 'Later' })).toBe('write');
    });

    it('classifies removals and completion/drop edits as dangerous', () => {
      expect(getToolAccessLevel('remove_item')).toBe('dangerous');
      expect(getToolAccessLevel('batch_remove_items')).toBe('dangerous');
      expect(getToolAccessLevel('edit_item', { newStatus: 'completed' })).toBe('dangerous');
      expect(getToolAccessLevel('edit_item', { newProjectStatus: 'dropped' })).toBe('dangerous');
    });

    it('classifies broad batch adds as dangerous', () => {
      const items = Array.from({ length: 11 }, (_, index) => ({
        type: 'task',
        name: `Task ${index}`,
      }));

      expect(getToolAccessLevel('batch_add_items', { items })).toBe('dangerous');
    });
  });

  describe('mode checks', () => {
    it('allows reads in readonly mode', () => {
      expect(isToolAllowed('query_omnifocus', {}, 'readonly')).toBe(true);
    });

    it('blocks writes in readonly mode', () => {
      expect(isToolAllowed('add_omnifocus_task', { name: 'Draft' }, 'readonly')).toBe(false);
    });

    it('allows ordinary writes in write mode', () => {
      expect(isToolAllowed('add_omnifocus_task', { name: 'Draft' }, 'write')).toBe(true);
    });

    it('blocks dangerous operations in write mode', () => {
      expect(isToolAllowed('remove_item', { id: 'abc', itemType: 'task' }, 'write')).toBe(false);
      expect(isToolAllowed('edit_item', { newStatus: 'completed' }, 'write')).toBe(false);
    });

    it('allows dangerous operations only in dangerous mode', () => {
      expect(isToolAllowed('remove_item', { id: 'abc', itemType: 'task' }, 'dangerous')).toBe(true);
    });

    it('detects dangerous dry-run mode', () => {
      expect(isDangerousDryRunEnabled({})).toBe(false);
      expect(isDangerousDryRunEnabled({ OMNIFOCUS_MCP_DANGEROUS_DRY_RUN: '1' })).toBe(true);
      expect(isDangerousDryRunEnabled({ OMNIFOCUS_MCP_DANGEROUS_DRY_RUN: 'true' })).toBe(true);
    });
  });

  describe('guardToolHandler', () => {
    it('does not call blocked handlers', async () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'created' }],
      });
      const guardedHandler = guardToolHandler('add_omnifocus_task', handler);

      const originalMode = process.env.OMNIFOCUS_MCP_MODE;
      delete process.env.OMNIFOCUS_MCP_MODE;

      try {
        const result = await guardedHandler({ name: 'Draft' }, {} as any);

        expect(handler).not.toHaveBeenCalled();
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain('blocked by OmniFocus MCP safety policy');
      } finally {
        if (originalMode === undefined) {
          delete process.env.OMNIFOCUS_MCP_MODE;
        } else {
          process.env.OMNIFOCUS_MCP_MODE = originalMode;
        }
      }
    });

    it('calls allowed handlers', async () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'queried' }],
      });
      const guardedHandler = guardToolHandler('query_omnifocus', handler);

      const result = await guardedHandler({ entity: 'tasks' }, {} as any);

      expect(handler).toHaveBeenCalledOnce();
      expect(result.content[0].text).toBe('queried');
    });

    it('blocks dangerous handlers without a grant even in dangerous mode', async () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'removed' }],
      });
      const guardedHandler = guardToolHandler('remove_item', handler);

      const originalMode = process.env.OMNIFOCUS_MCP_MODE;
      process.env.OMNIFOCUS_MCP_MODE = 'dangerous';

      try {
        const result = await guardedHandler({ name: 'Draft', itemType: 'task' }, {} as any);

        expect(handler).not.toHaveBeenCalled();
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain('requires a valid dangerousGrant');
      } finally {
        if (originalMode === undefined) {
          delete process.env.OMNIFOCUS_MCP_MODE;
        } else {
          process.env.OMNIFOCUS_MCP_MODE = originalMode;
        }
      }
    });

    it('calls dangerous handlers with a valid exact grant and strips it from args', async () => {
      resetDangerousGrantReplayCache();
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'removed' }],
      });
      const guardedHandler = guardToolHandler('remove_item', handler);
      const args = { name: 'Draft', itemType: 'task' };
      const claims = createExactDangerousGrantClaims({
        toolName: 'remove_item',
        args,
        expiresInSeconds: 60,
        jti: 'policy-grant-1',
      });
      const dangerousGrant = createDangerousGrantToken(claims, privateKeyPem);

      const originalMode = process.env.OMNIFOCUS_MCP_MODE;
      const originalPublicKey = process.env.OMNIFOCUS_MCP_DANGEROUS_GRANT_PUBLIC_KEY;
      process.env.OMNIFOCUS_MCP_MODE = 'dangerous';
      process.env.OMNIFOCUS_MCP_DANGEROUS_GRANT_PUBLIC_KEY = publicKeyPem;

      try {
        const result = await guardedHandler({ ...args, dangerousGrant }, {} as any);

        expect(handler).toHaveBeenCalledWith(args, {});
        expect(result.content[0].text).toBe('removed');
      } finally {
        if (originalMode === undefined) {
          delete process.env.OMNIFOCUS_MCP_MODE;
        } else {
          process.env.OMNIFOCUS_MCP_MODE = originalMode;
        }
        if (originalPublicKey === undefined) {
          delete process.env.OMNIFOCUS_MCP_DANGEROUS_GRANT_PUBLIC_KEY;
        } else {
          process.env.OMNIFOCUS_MCP_DANGEROUS_GRANT_PUBLIC_KEY = originalPublicKey;
        }
      }
    });

    it('verifies grants but skips dangerous handlers in dry-run mode', async () => {
      resetDangerousGrantReplayCache();
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'removed' }],
      });
      const guardedHandler = guardToolHandler('remove_item', handler);
      const args = { name: 'Draft', itemType: 'task' };
      const claims = createExactDangerousGrantClaims({
        toolName: 'remove_item',
        args,
        expiresInSeconds: 60,
        jti: 'policy-grant-dry-run-1',
      });
      const dangerousGrant = createDangerousGrantToken(claims, privateKeyPem);

      const originalMode = process.env.OMNIFOCUS_MCP_MODE;
      const originalPublicKey = process.env.OMNIFOCUS_MCP_DANGEROUS_GRANT_PUBLIC_KEY;
      const originalDryRun = process.env.OMNIFOCUS_MCP_DANGEROUS_DRY_RUN;
      process.env.OMNIFOCUS_MCP_MODE = 'dangerous';
      process.env.OMNIFOCUS_MCP_DANGEROUS_GRANT_PUBLIC_KEY = publicKeyPem;
      process.env.OMNIFOCUS_MCP_DANGEROUS_DRY_RUN = '1';

      try {
        const result = await guardedHandler({ ...args, dangerousGrant }, {} as any);

        expect(handler).not.toHaveBeenCalled();
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain('Dangerous dry run');
        expect(result.content[0].text).toContain('no OmniFocus mutation was executed');
      } finally {
        if (originalMode === undefined) {
          delete process.env.OMNIFOCUS_MCP_MODE;
        } else {
          process.env.OMNIFOCUS_MCP_MODE = originalMode;
        }
        if (originalPublicKey === undefined) {
          delete process.env.OMNIFOCUS_MCP_DANGEROUS_GRANT_PUBLIC_KEY;
        } else {
          process.env.OMNIFOCUS_MCP_DANGEROUS_GRANT_PUBLIC_KEY = originalPublicKey;
        }
        if (originalDryRun === undefined) {
          delete process.env.OMNIFOCUS_MCP_DANGEROUS_DRY_RUN;
        } else {
          process.env.OMNIFOCUS_MCP_DANGEROUS_DRY_RUN = originalDryRun;
        }
      }
    });
  });

  describe('blockedToolResult', () => {
    it('tells callers which mode is required', () => {
      const result = blockedToolResult('remove_item', {}, 'write');

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('required mode is "dangerous"');
      expect(result.content[0].text).toContain('OMNIFOCUS_MCP_MODE=dangerous');
    });

    it('explains missing or invalid grants', () => {
      const result = dangerousGrantRequiredResult('remove_item', 'Missing dangerousGrant.');

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('requires a valid dangerousGrant');
      expect(result.content[0].text).toContain('Missing dangerousGrant');
    });

    it('explains dangerous dry-run skips', () => {
      const result = dangerousDryRunResult('remove_item');

      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain('grant verified');
      expect(result.content[0].text).toContain('no OmniFocus mutation was executed');
    });
  });
});

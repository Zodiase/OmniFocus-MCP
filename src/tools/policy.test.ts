import { describe, expect, it, vi } from 'vitest';
import {
  blockedToolResult,
  getOmniFocusMcpMode,
  getToolAccessLevel,
  guardToolHandler,
  isToolAllowed,
} from './policy.js';

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
  });

  describe('blockedToolResult', () => {
    it('tells callers which mode is required', () => {
      const result = blockedToolResult('remove_item', {}, 'write');

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('required mode is "dangerous"');
      expect(result.content[0].text).toContain('OMNIFOCUS_MCP_MODE=dangerous');
    });
  });
});

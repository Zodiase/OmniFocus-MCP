import { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';

export type OmniFocusMcpMode = 'readonly' | 'write' | 'dangerous';
export type ToolAccessLevel = 'read' | 'write' | 'dangerous';

export type ToolResult = {
  content: Array<{
    type: 'text';
    text: string;
  }>;
  isError?: boolean;
};

type ToolHandler = (args: any, extra: RequestHandlerExtra) => Promise<ToolResult>;

const READ_TOOLS = new Set([
  'dump_database',
  'query_omnifocus',
  'list_perspectives',
  'get_perspective_view',
  'list_tags',
]);

const WRITE_TOOLS = new Set([
  'add_omnifocus_task',
  'add_project',
  'edit_item',
  'batch_add_items',
  'create_tag',
]);

const DANGEROUS_TOOLS = new Set([
  'remove_item',
  'batch_remove_items',
]);

const WRITE_MODES: OmniFocusMcpMode[] = ['write', 'dangerous'];
const DANGEROUS_MODES: OmniFocusMcpMode[] = ['dangerous'];
const BROAD_BATCH_ITEM_LIMIT = 10;

export function getOmniFocusMcpMode(env = process.env): OmniFocusMcpMode {
  const mode = env.OMNIFOCUS_MCP_MODE;

  if (mode === 'write' || mode === 'dangerous') {
    return mode;
  }

  return 'readonly';
}

export function getToolAccessLevel(toolName: string, args: any = {}): ToolAccessLevel {
  if (READ_TOOLS.has(toolName)) {
    return 'read';
  }

  if (DANGEROUS_TOOLS.has(toolName)) {
    return 'dangerous';
  }

  if (toolName === 'edit_item' && isDestructiveEdit(args)) {
    return 'dangerous';
  }

  if (toolName === 'batch_add_items' && isBroadBatch(args)) {
    return 'dangerous';
  }

  if (WRITE_TOOLS.has(toolName)) {
    return 'write';
  }

  return 'dangerous';
}

export function isToolAllowed(toolName: string, args: any, mode = getOmniFocusMcpMode()): boolean {
  const accessLevel = getToolAccessLevel(toolName, args);

  if (accessLevel === 'read') {
    return true;
  }

  if (accessLevel === 'write') {
    return WRITE_MODES.includes(mode);
  }

  return DANGEROUS_MODES.includes(mode);
}

export function blockedToolResult(toolName: string, args: any, mode = getOmniFocusMcpMode()): ToolResult {
  const accessLevel = getToolAccessLevel(toolName, args);
  const requiredMode = accessLevel === 'dangerous'
    ? 'dangerous'
    : 'write or dangerous';

  return {
    content: [{
      type: 'text',
      text: `Tool "${toolName}" is blocked by OmniFocus MCP safety policy. Current mode is "${mode}"; required mode is "${requiredMode}". Set OMNIFOCUS_MCP_MODE=${accessLevel === 'dangerous' ? 'dangerous' : 'write'} to allow this operation.`
    }],
    isError: true,
  };
}

export function guardToolHandler(toolName: string, handler: ToolHandler): ToolHandler {
  return async (args: any, extra: RequestHandlerExtra) => {
    const mode = getOmniFocusMcpMode();

    if (!isToolAllowed(toolName, args, mode)) {
      return blockedToolResult(toolName, args, mode);
    }

    return handler(args, extra);
  };
}

function isDestructiveEdit(args: any): boolean {
  return ['completed', 'dropped', 'skipped'].includes(args?.newStatus)
    || ['completed', 'dropped'].includes(args?.newProjectStatus);
}

function isBroadBatch(args: any): boolean {
  return Array.isArray(args?.items) && args.items.length > BROAD_BATCH_ITEM_LIMIT;
}

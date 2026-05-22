/**
 * MCP Server Requirements Test Suite
 *
 * Validates that the Encrypted Mailbox MCP server meets all Prometheus Protocol requirements:
 * 1. Tool discovery via JSON-RPC (tools/list endpoint)
 * 2. Owner system (get_owner method)
 * 3. Wallet/treasury system (get_treasury_balance method)
 * 4. ICRC-120 upgrade status (icrc120_upgrade_finished method)
 * 5. API key system
 */

import { describe, beforeAll, afterAll, it, expect, inject } from 'vitest';
import { PocketIc, createIdentity } from '@dfinity/pic';
import { IDL } from '@icp-sdk/core/candid';
import { AnonymousIdentity } from '@icp-sdk/core/agent';
import { Principal } from '@icp-sdk/core/principal';
import { idlFactory as mcpServerIdlFactory } from '../.dfx/local/canisters/encrypted-mailbox/service.did.js';
import type { _SERVICE as McpServerService } from '../.dfx/local/canisters/encrypted-mailbox/service.did.d.ts';
import type { Actor } from '@dfinity/pic';
import path from 'node:path';

const MCP_SERVER_WASM_PATH = path.resolve(
  __dirname,
  '../.dfx/local/canisters/encrypted-mailbox/encrypted-mailbox.wasm',
);

describe('MCP Server Requirements', () => {
  let pic: PocketIc;
  let serverActor: Actor<McpServerService>;
  let canisterId: Principal;
  let testOwner = createIdentity('test-owner');
  let ownerApiKey: string;

  beforeAll(async () => {
    const picUrl = inject('PIC_URL');
    pic = await PocketIc.create(picUrl);
    canisterId = await pic.createCanister();

    const initArg = IDL.encode(
      [IDL.Opt(IDL.Record({ owner: IDL.Opt(IDL.Principal) }))],
      [[{ owner: [testOwner.getPrincipal()] }]],
    );

    await pic.installCode({
      canisterId,
      wasm: MCP_SERVER_WASM_PATH,
      caller: testOwner,
      arg: initArg.buffer as ArrayBufferLike,
    });

    serverActor = pic.createActor<McpServerService>(
      mcpServerIdlFactory,
      canisterId,
    );

    // Disable vetKD encryption for PocketIc tests
    serverActor.setIdentity(testOwner);
    await serverActor.set_encryption_enabled(false);

    // Create API key for owner
    serverActor.setIdentity(testOwner);
    ownerApiKey = await serverActor.create_my_api_key('owner-key', ['openid']);
  });

  afterAll(async () => {
    await pic?.tearDown();
  });

  describe('JSON-RPC Tool Discovery', () => {
    it('should respond to tools/list request via http_request_update', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const rpcPayload = {
        jsonrpc: '2.0',
        method: 'tools/list',
        params: {},
        id: 'test-tools-list',
      };
      const body = new TextEncoder().encode(JSON.stringify(rpcPayload));
      const httpResponse = await serverActor.http_request_update({
        method: 'POST',
        url: '/mcp',
        headers: [['Content-Type', 'application/json'], ['X-API-Key', ownerApiKey]],
        body,
        certificate_version: [],
      });
      expect(httpResponse.status_code).toBe(200);
    });

    it('should return valid JSON-RPC response with tools array', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const rpcPayload = {
        jsonrpc: '2.0',
        method: 'tools/list',
        params: {},
        id: 'test-tools-list',
      };
      const body = new TextEncoder().encode(JSON.stringify(rpcPayload));
      const httpResponse = await serverActor.http_request_update({
        method: 'POST',
        url: '/mcp',
        headers: [['Content-Type', 'application/json'], ['X-API-Key', ownerApiKey]],
        body,
        certificate_version: [],
      });
      const responseBody = JSON.parse(
        new TextDecoder().decode(httpResponse.body as Uint8Array),
      );
      expect(responseBody).toHaveProperty('jsonrpc', '2.0');
      expect(responseBody).toHaveProperty('id', 'test-tools-list');
      expect(responseBody).not.toHaveProperty('error');
      expect(responseBody).toHaveProperty('result');
      expect(responseBody.result).toHaveProperty('tools');
      expect(Array.isArray(responseBody.result.tools)).toBe(true);
    });

    it('should return 5 tools with required fields', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const rpcPayload = {
        jsonrpc: '2.0',
        method: 'tools/list',
        params: {},
        id: 'test-tools-list',
      };
      const body = new TextEncoder().encode(JSON.stringify(rpcPayload));
      const httpResponse = await serverActor.http_request_update({
        method: 'POST',
        url: '/mcp',
        headers: [['Content-Type', 'application/json'], ['X-API-Key', ownerApiKey]],
        body,
        certificate_version: [],
      });
      const responseBody = JSON.parse(
        new TextDecoder().decode(httpResponse.body as Uint8Array),
      );
      const tools = responseBody.result.tools;
      expect(tools.length).toBe(5);

      const toolNames = tools.map((t: any) => t.name).sort();
      expect(toolNames).toEqual([
        'delete_message',
        'get_inbox',
        'get_inbox_count',
        'read_message',
        'send_message',
      ]);

      tools.forEach((tool: any) => {
        expect(tool).toHaveProperty('name');
        expect(typeof tool.name).toBe('string');
        expect(tool.name.length).toBeGreaterThan(0);
        if (tool.description !== undefined) {
          expect(typeof tool.description).toBe('string');
        }
        if (tool.inputSchema !== undefined) {
          expect(typeof tool.inputSchema).toBe('object');
        }
      });
    });
  });

  describe('Owner System', () => {
    it('should have get_owner method', async () => {
      // @ts-ignore
      const owner = await serverActor.get_owner();
      expect(owner).toBeDefined();
      expect(typeof owner.toText).toBe('function');
    });

    it('should return a valid Principal as owner', async () => {
      // @ts-ignore
      const owner = await serverActor.get_owner();
      const ownerText = owner.toText();
      expect(typeof ownerText).toBe('string');
      expect(ownerText.length).toBeGreaterThan(0);
      expect(ownerText).not.toBe('2vxsx-fae');
    });
  });

  describe('Wallet/Treasury System', () => {
    it('should have get_treasury_balance method', async () => {
      const dummyLedgerId = Principal.fromText('aaaaa-aa');
      // @ts-ignore
      const balance = await serverActor.get_treasury_balance(dummyLedgerId);
      expect(balance).toBeDefined();
    });

    it('should return a numeric balance', async () => {
      const dummyLedgerId = Principal.fromText('aaaaa-aa');
      // @ts-ignore
      const balance = await serverActor.get_treasury_balance(dummyLedgerId);
      const isNumeric = typeof balance === 'bigint' || typeof balance === 'number';
      expect(isNumeric).toBe(true);
      if (typeof balance === 'bigint') {
        expect(balance >= 0n).toBe(true);
      } else {
        expect(balance >= 0).toBe(true);
      }
    });
  });

  describe('ICRC-120 Upgrade System', () => {
    it('should have icrc120_upgrade_finished method', async () => {
      // @ts-ignore
      const result = await serverActor.icrc120_upgrade_finished();
      expect(result).toBeDefined();
    });

    it('should return valid upgrade status', async () => {
      // @ts-ignore
      const result = await serverActor.icrc120_upgrade_finished();
      expect(result).toBeDefined();
      const hasValidKey =
        'Success' in result ||
        'InProgress' in result ||
        'Failed' in result;
      expect(hasValidKey).toBe(true);
      if ('Success' in result) {
        const timestamp = result.Success;
        expect(typeof timestamp === 'bigint' || typeof timestamp === 'number').toBe(true);
        if (typeof timestamp === 'bigint') {
          expect(timestamp > 0n).toBe(true);
        } else {
          expect(timestamp > 0).toBe(true);
        }
      }
    });
  });

  describe('Complete System Integration', () => {
    it('should meet all requirements', async () => {
      const requirements = {
        toolDiscovery: false,
        ownerSystem: false,
        walletSystem: false,
        icrc120: false,
      };

      try {
        serverActor.setIdentity(new AnonymousIdentity());
        const rpcPayload = {
          jsonrpc: '2.0',
          method: 'tools/list',
          params: {},
          id: 'integration-test',
        };
        const body = new TextEncoder().encode(JSON.stringify(rpcPayload));
        const httpResponse = await serverActor.http_request_update({
          method: 'POST',
          url: '/mcp',
          headers: [['Content-Type', 'application/json'], ['X-API-Key', ownerApiKey]],
          body,
          certificate_version: [],
        });
        if (httpResponse.status_code === 200) {
          const responseBody = JSON.parse(
            new TextDecoder().decode(httpResponse.body as Uint8Array),
          );
          if (responseBody.result?.tools && Array.isArray(responseBody.result.tools)) {
            requirements.toolDiscovery = true;
          }
        }
      } catch (e) {}

      try {
        // @ts-ignore
        const owner = await serverActor.get_owner();
        if (owner && typeof owner.toText === 'function') {
          requirements.ownerSystem = true;
        }
      } catch (e) {}

      try {
        const dummyLedgerId = Principal.fromText('aaaaa-aa');
        // @ts-ignore
        const balance = await serverActor.get_treasury_balance(dummyLedgerId);
        if (typeof balance === 'bigint' || typeof balance === 'number') {
          requirements.walletSystem = true;
        }
      } catch (e) {}

      try {
        // @ts-ignore
        const result = await serverActor.icrc120_upgrade_finished();
        if (result && ('Success' in result || 'InProgress' in result || 'Failed' in result)) {
          requirements.icrc120 = true;
        }
      } catch (e) {}

      expect(requirements.toolDiscovery).toBe(true);
      expect(requirements.ownerSystem).toBe(true);
      expect(requirements.walletSystem).toBe(true);
      expect(requirements.icrc120).toBe(true);

      console.log('\n✅ MCP Server Requirements Summary:');
      console.log(`   📡 Tool Discovery (JSON-RPC): ${requirements.toolDiscovery ? '✅' : '❌'}`);
      console.log(`   👤 Owner System: ${requirements.ownerSystem ? '✅' : '❌'}`);
      console.log(`   💰 Wallet/Treasury System: ${requirements.walletSystem ? '✅' : '❌'}`);
      console.log(`   🔄 ICRC-120 Upgrade: ${requirements.icrc120 ? '✅' : '❌'}`);
    });
  });
});

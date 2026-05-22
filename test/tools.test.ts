/**
 * Encrypted Mailbox Tool Tests
 *
 * Tests all 5 tools: send_message, get_inbox, read_message, delete_message, get_inbox_count
 * Tests auth requirements, principal isolation, pagination, and edge cases.
 */

import { describe, beforeAll, afterAll, it, expect, inject } from 'vitest';
import { PocketIc, createIdentity } from '@dfinity/pic';
import { IDL } from '@icp-sdk/core/candid';
import { AnonymousIdentity } from '@icp-sdk/core/agent';
import { idlFactory as mcpServerIdlFactory } from '../.dfx/local/canisters/encrypted-mailbox/service.did.js';
import type { _SERVICE as McpServerService } from '../.dfx/local/canisters/encrypted-mailbox/service.did.d.ts';
import type { Actor } from '@dfinity/pic';
import path from 'node:path';

const MCP_SERVER_WASM_PATH = path.resolve(
  __dirname,
  '../.dfx/local/canisters/encrypted-mailbox/encrypted-mailbox.wasm',
);

// Helper to make an MCP tool call with optional API key
async function callTool(
  actor: Actor<McpServerService>,
  toolName: string,
  args: Record<string, any>,
  apiKey?: string,
  id: string = 'test-' + toolName,
) {
  const rpcPayload = {
    jsonrpc: '2.0',
    method: 'tools/call',
    params: { name: toolName, arguments: args },
    id,
  };
  const body = new TextEncoder().encode(JSON.stringify(rpcPayload));
  const headers: [string, string][] = [['Content-Type', 'application/json']];
  if (apiKey) {
    headers.push(['X-API-Key', apiKey]);
  }
  const httpResponse = await actor.http_request_update({
    method: 'POST',
    url: '/mcp',
    headers,
    body,
    certificate_version: [],
  });
  if (httpResponse.status_code !== 200) {
    const bodyText = new TextDecoder().decode(httpResponse.body as Uint8Array);
    return {
      _status: httpResponse.status_code,
      _body: bodyText,
      result: {
        isError: true,
        content: [{ text: `HTTP ${httpResponse.status_code}: ${bodyText}` }],
      },
    };
  }
  const responseBody = JSON.parse(
    new TextDecoder().decode(httpResponse.body as Uint8Array),
  );
  return responseBody;
}

// Helper to parse the tool result text as JSON
function parseResult(response: any): any {
  const text = response.result.content[0].text;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

describe('Encrypted Mailbox Tools', () => {
  let pic: PocketIc;
  let serverActor: Actor<McpServerService>;
  let canisterId: any;
  let testOwner = createIdentity('test-owner');
  let alice = createIdentity('alice');
  let bob = createIdentity('bob');
  let charlie = createIdentity('charlie');
  let aliceApiKey: string;
  let bobApiKey: string;
  let charlieApiKey: string;

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
      arg: initArg.buffer as ArrayBufferLike,
    });

    serverActor = pic.createActor<McpServerService>(
      mcpServerIdlFactory,
      canisterId,
    );

    // Disable vetKD encryption for PocketIc tests (no vetKD available locally)
    serverActor.setIdentity(testOwner);
    await serverActor.set_encryption_enabled(false);

    // Create API keys for test users
    serverActor.setIdentity(alice);
    aliceApiKey = await serverActor.create_my_api_key('alice-key', ['openid']);

    serverActor.setIdentity(bob);
    bobApiKey = await serverActor.create_my_api_key('bob-key', ['openid']);

    serverActor.setIdentity(charlie);
    charlieApiKey = await serverActor.create_my_api_key('charlie-key', ['openid']);
  });

  afterAll(async () => {
    await pic?.tearDown();
  });

  // ==================== AUTH TESTS ====================

  describe('Authentication', () => {
    it('should reject unauthenticated callers for send_message', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'send_message', {
        to: bob.getPrincipal().toText(),
        subject: 'Test',
        body: 'Hello',
      });
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for get_inbox', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'get_inbox', {});
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for read_message', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'read_message', { message_id: 'msg-1' });
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for delete_message', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'delete_message', { message_id: 'msg-1' });
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for get_inbox_count', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'get_inbox_count', {});
      expect(response._status === 401 || response.result.isError).toBe(true);
    });
  });

  // ==================== SEND MESSAGE ====================

  describe('send_message', () => {
    it('should send a message to another principal', async () => {
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'send_message',
        {
          to: bob.getPrincipal().toText(),
          subject: 'API Key Delivery',
          body: 'Here is the API key: sk-secret-12345',
        },
        aliceApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.message_id).toBe('msg-1');
      expect(result.sender).toBe(alice.getPrincipal().toText());
      expect(result.recipient).toBe(bob.getPrincipal().toText());
      expect(result.subject).toBe('API Key Delivery');
      expect(result.timestamp).toBeGreaterThan(0);
    });

    it('should send a second message', async () => {
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'send_message',
        {
          to: bob.getPrincipal().toText(),
          subject: 'Follow up',
          body: 'Did you get the key?',
        },
        aliceApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.message_id).toBe('msg-2');
    });

    it('should allow sending a message to yourself', async () => {
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'send_message',
        {
          to: alice.getPrincipal().toText(),
          subject: 'Note to self',
          body: 'Remember to rotate keys',
        },
        aliceApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.sender).toBe(alice.getPrincipal().toText());
      expect(result.recipient).toBe(alice.getPrincipal().toText());
    });

    it('should reject invalid principal format', async () => {
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'send_message',
        {
          to: 'not-a-valid-principal!!!',
          subject: 'Test',
          body: 'Hello',
        },
        aliceApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('INVALID_INPUT');
    });

    it('should reject empty subject', async () => {
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'send_message',
        {
          to: bob.getPrincipal().toText(),
          subject: '',
          body: 'Hello',
        },
        aliceApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('INVALID_INPUT');
    });

    it('should reject empty body', async () => {
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'send_message',
        {
          to: bob.getPrincipal().toText(),
          subject: 'Test',
          body: '',
        },
        aliceApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('INVALID_INPUT');
    });

    it('should reject missing to field', async () => {
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'send_message',
        {
          subject: 'Test',
          body: 'Hello',
        },
        aliceApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('INVALID_INPUT');
    });

    it('should send to a principal that has never used the service', async () => {
      const stranger = createIdentity('stranger');
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'send_message',
        {
          to: stranger.getPrincipal().toText(),
          subject: 'Welcome',
          body: 'You have mail!',
        },
        aliceApiKey,
      );
      expect(response.result.isError).toBe(false);
    });
  });

  // ==================== GET INBOX COUNT ====================

  describe('get_inbox_count', () => {
    it('should return correct counts for Bob (2 messages from Alice)', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(serverActor, 'get_inbox_count', {}, bobApiKey);
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBe(2);
      expect(result.unread).toBe(2);
    });

    it('should return 0 for Charlie (no messages)', async () => {
      serverActor.setIdentity(charlie);
      const response = await callTool(serverActor, 'get_inbox_count', {}, charlieApiKey);
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBe(0);
      expect(result.unread).toBe(0);
    });
  });

  // ==================== GET INBOX ====================

  describe('get_inbox', () => {
    it('should list messages without bodies', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(serverActor, 'get_inbox', {}, bobApiKey);
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBe(2);
      expect(result.unread).toBe(2);
      expect(result.messages.length).toBe(2);
      // Ensure no body is returned
      for (const msg of result.messages) {
        expect(msg.body).toBeUndefined();
        expect(msg.message_id).toBeDefined();
        expect(msg.sender).toBeDefined();
        expect(msg.subject).toBeDefined();
        expect(msg.timestamp).toBeDefined();
        expect(msg.read).toBe(false);
      }
    });

    it('should return messages sorted by timestamp descending (newest first)', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(serverActor, 'get_inbox', {}, bobApiKey);
      const result = parseResult(response);
      // msg-2 should be first (newer)
      expect(result.messages[0].message_id).toBe('msg-2');
      expect(result.messages[1].message_id).toBe('msg-1');
    });

    it('should support pagination', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(
        serverActor,
        'get_inbox',
        { limit: 1, offset: 0 },
        bobApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.messages.length).toBe(1);
      expect(result.total).toBe(2);
    });

    it('should support pagination offset', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(
        serverActor,
        'get_inbox',
        { limit: 1, offset: 1 },
        bobApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.messages.length).toBe(1);
      expect(result.messages[0].message_id).toBe('msg-1');
    });

    it('should return empty for Charlie', async () => {
      serverActor.setIdentity(charlie);
      const response = await callTool(serverActor, 'get_inbox', {}, charlieApiKey);
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBe(0);
      expect(result.messages).toEqual([]);
    });
  });

  // ==================== READ MESSAGE ====================

  describe('read_message', () => {
    it('should decrypt and return the message body', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(
        serverActor,
        'read_message',
        { message_id: 'msg-1' },
        bobApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.message_id).toBe('msg-1');
      expect(result.sender).toBe(alice.getPrincipal().toText());
      expect(result.recipient).toBe(bob.getPrincipal().toText());
      expect(result.subject).toBe('API Key Delivery');
      expect(result.body).toBe('Here is the API key: sk-secret-12345');
      expect(result.read).toBe(true);
      expect(result.timestamp).toBeGreaterThan(0);
    });

    it('should mark message as read', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(serverActor, 'get_inbox_count', {}, bobApiKey);
      const result = parseResult(response);
      expect(result.total).toBe(2);
      expect(result.unread).toBe(1); // msg-1 was just read
    });

    it('should return NOT_FOUND for non-existent message', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(
        serverActor,
        'read_message',
        { message_id: 'msg-999' },
        bobApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('NOT_FOUND');
    });

    it('should not allow Alice to read Bob\'s messages', async () => {
      serverActor.setIdentity(alice);
      const response = await callTool(
        serverActor,
        'read_message',
        { message_id: 'msg-1' },
        aliceApiKey,
      );
      // Alice's inbox doesn't contain msg-1 (it's in Bob's inbox)
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('NOT_FOUND');
    });

    it('should filter unread_only correctly after reading', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(
        serverActor,
        'get_inbox',
        { unread_only: true },
        bobApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBe(1); // Only msg-2 is unread
      expect(result.messages[0].message_id).toBe('msg-2');
    });
  });

  // ==================== DELETE MESSAGE ====================

  describe('delete_message', () => {
    it('should delete an existing message', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(
        serverActor,
        'delete_message',
        { message_id: 'msg-1' },
        bobApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.message_id).toBe('msg-1');
      expect(result.deleted).toBe(true);
    });

    it('should be idempotent — deleting again returns deleted=false', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(
        serverActor,
        'delete_message',
        { message_id: 'msg-1' },
        bobApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.deleted).toBe(false);
    });

    it('should return deleted=false for non-existent message', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(
        serverActor,
        'delete_message',
        { message_id: 'msg-never-existed' },
        bobApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.deleted).toBe(false);
    });

    it('should update inbox count after deletion', async () => {
      serverActor.setIdentity(bob);
      const response = await callTool(serverActor, 'get_inbox_count', {}, bobApiKey);
      const result = parseResult(response);
      expect(result.total).toBe(1); // Only msg-2 remains
      expect(result.unread).toBe(1);
    });
  });

  // ==================== PRINCIPAL ISOLATION ====================

  describe('Principal Isolation', () => {
    it('different principals cannot see each other\'s inboxes', async () => {
      // Charlie should have no messages
      serverActor.setIdentity(charlie);
      const response = await callTool(serverActor, 'get_inbox', {}, charlieApiKey);
      const result = parseResult(response);
      expect(result.total).toBe(0);
    });

    it('Bob sends to Charlie, Charlie can read it', async () => {
      // Bob sends to Charlie
      serverActor.setIdentity(bob);
      await callTool(
        serverActor,
        'send_message',
        {
          to: charlie.getPrincipal().toText(),
          subject: 'Hello Charlie',
          body: 'Welcome to the mailbox!',
        },
        bobApiKey,
      );

      // Charlie reads it
      serverActor.setIdentity(charlie);
      const countResp = await callTool(serverActor, 'get_inbox_count', {}, charlieApiKey);
      const count = parseResult(countResp);
      expect(count.total).toBe(1);
      expect(count.unread).toBe(1);

      const inboxResp = await callTool(serverActor, 'get_inbox', {}, charlieApiKey);
      const inbox = parseResult(inboxResp);
      expect(inbox.messages[0].sender).toBe(bob.getPrincipal().toText());
      expect(inbox.messages[0].subject).toBe('Hello Charlie');

      const readResp = await callTool(
        serverActor,
        'read_message',
        { message_id: inbox.messages[0].message_id },
        charlieApiKey,
      );
      const msg = parseResult(readResp);
      expect(msg.body).toBe('Welcome to the mailbox!');
    });
  });

  // ==================== FULL DEMO FLOW ====================

  describe('Demo Flow (spec section 16)', () => {
    it('should complete the full demo flow', async () => {
      // 1. Alice sends to Bob
      serverActor.setIdentity(alice);
      const sendResp = await callTool(
        serverActor,
        'send_message',
        {
          to: bob.getPrincipal().toText(),
          subject: 'Secret Credentials',
          body: 'API key: sk-demo-secret-key-42',
        },
        aliceApiKey,
      );
      expect(sendResp.result.isError).toBe(false);
      const sent = parseResult(sendResp);
      const msgId = sent.message_id;

      // 2. Bob checks count
      serverActor.setIdentity(bob);
      const count1 = parseResult(
        await callTool(serverActor, 'get_inbox_count', {}, bobApiKey),
      );
      expect(count1.unread).toBeGreaterThanOrEqual(1);

      // 3. Bob gets inbox (sees metadata, no body)
      const inbox = parseResult(
        await callTool(serverActor, 'get_inbox', {}, bobApiKey),
      );
      const found = inbox.messages.find((m: any) => m.message_id === msgId);
      expect(found).toBeDefined();
      expect(found.body).toBeUndefined();

      // 4. Bob reads the message (decrypted body)
      const readResp = parseResult(
        await callTool(serverActor, 'read_message', { message_id: msgId }, bobApiKey),
      );
      expect(readResp.body).toBe('API key: sk-demo-secret-key-42');

      // 5. Bob checks count again (unread decreased)
      const count2 = parseResult(
        await callTool(serverActor, 'get_inbox_count', {}, bobApiKey),
      );
      expect(count2.unread).toBeLessThan(count1.unread);

      // 6. Bob replies to Alice
      const replyResp = await callTool(
        serverActor,
        'send_message',
        {
          to: alice.getPrincipal().toText(),
          subject: 'Re: Secret Credentials',
          body: 'Got it, thanks!',
        },
        bobApiKey,
      );
      expect(replyResp.result.isError).toBe(false);

      // 7. Bob deletes the message
      const delResp = parseResult(
        await callTool(serverActor, 'delete_message', { message_id: msgId }, bobApiKey),
      );
      expect(delResp.deleted).toBe(true);

      // 8. Verify Alice got the reply
      serverActor.setIdentity(alice);
      const aliceInbox = parseResult(
        await callTool(serverActor, 'get_inbox', {}, aliceApiKey),
      );
      const reply = aliceInbox.messages.find(
        (m: any) => m.subject === 'Re: Secret Credentials',
      );
      expect(reply).toBeDefined();
    });
  });
});

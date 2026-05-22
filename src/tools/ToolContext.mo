import Principal "mo:base/Principal";
import Result "mo:base/Result";
import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Json "mo:json";
import Map "mo:map/Map";
import Time "mo:base/Time";
import Int "mo:base/Int";
import Nat "mo:base/Nat";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";

import Encryption "../Encryption";

module ToolContext {

  // --- Message type ---
  public type Message = {
    id : Text;              // "msg-1", "msg-2", etc.
    sender : Principal;
    recipient : Principal;
    subject : Text;         // plaintext subject (visible in inbox listing)
    ciphertext : Blob;      // IBE-encrypted message body
    timestamp : Nat;        // nanosecond timestamp
    read : Bool;            // has recipient read this?
  };

  // --- Storage type: recipient Principal -> [Message] ---
  // Using Map<Principal, [Message]> for stable storage
  public type InboxStore = Map.Map<Principal, [Message]>;

  /// Context shared between tools and the main canister
  public type ToolContext = {
    canisterPrincipal : Principal;
    owner : Principal;
    appContext : McpTypes.AppContext;
    inbox : InboxStore;
    messageCounter : { var count : Nat };
    vetKdKeyId : Encryption.VetKdKeyId;
    encryptionEnabled : () -> Bool;
  };

  // --- Constants ---
  public let MAX_SUBJECT_LENGTH : Nat = 256;
  public let MAX_BODY_SIZE : Nat = 32_768; // 32KB
  public let MAX_INBOX_SIZE : Nat = 500;

  // --- Helpers ---

  public func now() : Nat {
    Int.abs(Time.now());
  };

  /// Generate the next message ID
  public func nextMessageId(counter : { var count : Nat }) : Text {
    counter.count += 1;
    "msg-" # Nat.toText(counter.count);
  };

  /// Get messages for a principal (returns empty array if none)
  public func getMessages(store : InboxStore, principal : Principal) : [Message] {
    switch (Map.get(store, Map.phash, principal)) {
      case (?msgs) { msgs };
      case (null) { [] };
    };
  };

  /// Set messages for a principal
  public func setMessages(store : InboxStore, principal : Principal, msgs : [Message]) {
    ignore Map.put(store, Map.phash, principal, msgs);
  };

  /// Append a message to a principal's inbox
  public func appendMessage(store : InboxStore, principal : Principal, msg : Message) {
    let existing = getMessages(store, principal);
    let buf = Buffer.fromArray<Message>(existing);
    buf.add(msg);
    setMessages(store, principal, Buffer.toArray(buf));
  };

  /// Count messages in a principal's inbox
  public func inboxSize(store : InboxStore, principal : Principal) : Nat {
    getMessages(store, principal).size();
  };

  /// Count unread messages in a principal's inbox
  public func unreadCount(store : InboxStore, principal : Principal) : Nat {
    let msgs = getMessages(store, principal);
    var count : Nat = 0;
    for (msg in msgs.vals()) {
      if (not msg.read) { count += 1 };
    };
    count;
  };

  /// Helper function to create an error response
  public func makeError(message : Text, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) {
    cb(#ok({ content = [#text({ text = "Error: " # message })]; isError = true; structuredContent = null }));
  };

  /// Helper function to create a success response with structured JSON
  public func makeSuccess(structured : Json.Json, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) {
    cb(#ok({ content = [#text({ text = Json.stringify(structured, null) })]; isError = false; structuredContent = ?structured }));
  };

  /// Helper to require auth and extract principal
  public func requireAuth(auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : ?Principal {
    switch (auth) {
      case (?a) {
        if (Principal.isAnonymous(a.principal)) {
          makeError("UNAUTHORIZED: Authentication required. Anonymous callers cannot access the mailbox.", cb);
          null;
        } else {
          ?a.principal;
        };
      };
      case (null) {
        makeError("UNAUTHORIZED: Authentication required. Please authenticate to access the mailbox.", cb);
        null;
      };
    };
  };

  /// Sort messages by timestamp descending (newest first)
  public func sortedMessages(msgs : [Message]) : [Message] {
    Array.sort<Message>(msgs, func(a : Message, b : Message) : {#less; #equal; #greater} {
      if (a.timestamp > b.timestamp) { #less }
      else if (a.timestamp < b.timestamp) { #greater }
      else { #equal };
    });
  };

  /// Replace a message at a given index in the array (for marking as read)
  public func replaceMessage(msgs : [Message], idx : Nat, newMsg : Message) : [Message] {
    Array.tabulate<Message>(msgs.size(), func(i : Nat) : Message {
      if (i == idx) { newMsg } else { msgs[i] };
    });
  };

  /// Remove a message at a given index from the array
  public func removeMessage(msgs : [Message], idx : Nat) : [Message] {
    let buf = Buffer.Buffer<Message>(msgs.size());
    var i : Nat = 0;
    for (msg in msgs.vals()) {
      if (i != idx) { buf.add(msg) };
      i += 1;
    };
    Buffer.toArray(buf);
  };
};

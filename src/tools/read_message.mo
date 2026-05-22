import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Principal "mo:base/Principal";
import Text "mo:base/Text";

import ToolContext "ToolContext";
import Encryption "../Encryption";

module {

  public func config() : McpTypes.Tool = {
    name = "read_message";
    title = ?"Read Message";
    description = ?"Read and decrypt a specific message from your inbox. The canister derives your vetKey decryption key and returns the plaintext body. Marks the message as read.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("message_id", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("The message ID to read")),
        ])),
      ])),
      ("required", Json.arr([Json.str("message_id")])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("message_id", Json.obj([("type", Json.str("string"))])),
        ("sender", Json.obj([("type", Json.str("string"))])),
        ("recipient", Json.obj([("type", Json.str("string"))])),
        ("subject", Json.obj([("type", Json.str("string"))])),
        ("body", Json.obj([("type", Json.str("string"))])),
        ("timestamp", Json.obj([("type", Json.str("number"))])),
        ("read", Json.obj([("type", Json.str("boolean"))])),
      ])),
      ("required", Json.arr([Json.str("message_id"), Json.str("sender"), Json.str("subject"), Json.str("body"), Json.str("timestamp")])),
    ]);
  };

  public func handle(context : ToolContext.ToolContext) : McpTypes.ToolFn {
    func(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {

      let caller = switch (ToolContext.requireAuth(auth, cb)) {
        case (?p) { p };
        case (null) { return };
      };

      let messageId = switch (Result.toOption(Json.getAsText(args, "message_id"))) {
        case (?id) { id };
        case (null) {
          return ToolContext.makeError("INVALID_INPUT: 'message_id' is required", cb);
        };
      };

      // Get caller's inbox messages
      let msgs = ToolContext.getMessages(context.inbox, caller);

      // Find the message
      var foundIdx : ?Nat = null;
      var foundMsg : ?ToolContext.Message = null;
      var i : Nat = 0;
      for (msg in msgs.vals()) {
        if (msg.id == messageId) {
          foundIdx := ?i;
          foundMsg := ?msg;
        };
        i += 1;
      };

      let (idx, msg) = switch (foundIdx, foundMsg) {
        case (?idx, ?msg) { (idx, msg) };
        case (_, _) {
          return ToolContext.makeError("NOT_FOUND: Message '" # messageId # "' not found", cb);
        };
      };

      // Verify caller is the recipient
      if (msg.recipient != caller) {
        return ToolContext.makeError("UNAUTHORIZED: You can only read messages addressed to you", cb);
      };

      // Decrypt the body
      let body = if (context.encryptionEnabled()) {
        let derivedKey = await Encryption.deriveKeyForPrincipal(caller, context.vetKdKeyId);
        switch (Encryption.decrypt(msg.ciphertext, messageId, derivedKey)) {
          case (?v) { v };
          case (null) {
            return ToolContext.makeError("DECRYPTION_FAILED: Could not decrypt message '" # messageId # "'", cb);
          };
        };
      } else {
        switch (Text.decodeUtf8(msg.ciphertext)) {
          case (?v) { v };
          case (null) {
            return ToolContext.makeError("DECRYPTION_FAILED: Could not decode message '" # messageId # "'", cb);
          };
        };
      };

      // Mark as read (replace the message in the array)
      if (not msg.read) {
        let updated : ToolContext.Message = {
          id = msg.id;
          sender = msg.sender;
          recipient = msg.recipient;
          subject = msg.subject;
          ciphertext = msg.ciphertext;
          timestamp = msg.timestamp;
          read = true;
        };
        let newMsgs = ToolContext.replaceMessage(msgs, idx, updated);
        ToolContext.setMessages(context.inbox, caller, newMsgs);
      };

      ToolContext.makeSuccess(
        Json.obj([
          ("message_id", Json.str(msg.id)),
          ("sender", Json.str(Principal.toText(msg.sender))),
          ("recipient", Json.str(Principal.toText(msg.recipient))),
          ("subject", Json.str(msg.subject)),
          ("body", Json.str(body)),
          ("timestamp", #number(#int(msg.timestamp))),
          ("read", Json.bool(true)),
        ]),
        cb,
      );
    };
  };
};

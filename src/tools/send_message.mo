import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Principal "mo:base/Principal";
import Text "mo:base/Text";

import ToolContext "ToolContext";
import Encryption "../Encryption";

module {

  /// Validate that a string looks like a valid principal text representation.
  /// Principals use lowercase alphanumeric chars (a-z, 0-9) separated by dashes.
  /// This prevents RTS traps from Principal.fromText on garbage input.
  func isValidPrincipalText(t : Text) : Bool {
    let len = t.size();
    if (len == 0 or len > 63) return false;
    for (c in t.chars()) {
      let valid = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-';
      if (not valid) return false;
    };
    true;
  };

  public func config() : McpTypes.Tool = {
    name = "send_message";
    title = ?"Send Message";
    description = ?"Send an encrypted message to any principal on ICP. The message body is encrypted using vetKey IBE — only the recipient can ever decrypt it. No registration or key exchange required.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("to", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("Recipient principal ID")),
        ])),
        ("subject", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("Message subject, max 256 chars")),
          ("maxLength", #number(#int(256))),
        ])),
        ("body", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("Message body, max 32KB")),
        ])),
      ])),
      ("required", Json.arr([Json.str("to"), Json.str("subject"), Json.str("body")])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("message_id", Json.obj([("type", Json.str("string"))])),
        ("sender", Json.obj([("type", Json.str("string"))])),
        ("recipient", Json.obj([("type", Json.str("string"))])),
        ("subject", Json.obj([("type", Json.str("string"))])),
        ("timestamp", Json.obj([("type", Json.str("number"))])),
      ])),
      ("required", Json.arr([Json.str("message_id"), Json.str("sender"), Json.str("recipient"), Json.str("subject"), Json.str("timestamp")])),
    ]);
  };

  public func handle(context : ToolContext.ToolContext) : McpTypes.ToolFn {
    func(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {

      // Require auth
      let sender = switch (ToolContext.requireAuth(auth, cb)) {
        case (?p) { p };
        case (null) { return };
      };

      // Parse "to" (recipient principal)
      let toText = switch (Result.toOption(Json.getAsText(args, "to"))) {
        case (?t) { t };
        case (null) {
          return ToolContext.makeError("INVALID_INPUT: 'to' (recipient principal) is required", cb);
        };
      };

      // Validate principal format before parsing (Principal.fromText traps on invalid input)
      if (not isValidPrincipalText(toText)) {
        return ToolContext.makeError("INVALID_INPUT: Invalid principal format for 'to': " # toText, cb);
      };

      let recipient = Principal.fromText(toText);

      if (Principal.isAnonymous(recipient)) {
        return ToolContext.makeError("INVALID_INPUT: Cannot send messages to the anonymous principal", cb);
      };

      // Parse subject
      let subject = switch (Result.toOption(Json.getAsText(args, "subject"))) {
        case (?s) { s };
        case (null) {
          return ToolContext.makeError("INVALID_INPUT: 'subject' is required", cb);
        };
      };

      if (subject.size() == 0) {
        return ToolContext.makeError("INVALID_INPUT: 'subject' cannot be empty", cb);
      };

      if (subject.size() > ToolContext.MAX_SUBJECT_LENGTH) {
        return ToolContext.makeError("INVALID_INPUT: 'subject' exceeds maximum length of 256 characters", cb);
      };

      // Parse body
      let body = switch (Result.toOption(Json.getAsText(args, "body"))) {
        case (?b) { b };
        case (null) {
          return ToolContext.makeError("INVALID_INPUT: 'body' is required", cb);
        };
      };

      if (body.size() == 0) {
        return ToolContext.makeError("INVALID_INPUT: 'body' cannot be empty", cb);
      };

      if (body.size() > ToolContext.MAX_BODY_SIZE) {
        return ToolContext.makeError("INVALID_INPUT: 'body' exceeds maximum size of 32KB", cb);
      };

      // Check recipient inbox capacity
      if (ToolContext.inboxSize(context.inbox, recipient) >= ToolContext.MAX_INBOX_SIZE) {
        return ToolContext.makeError("LIMIT_EXCEEDED: Recipient inbox has reached maximum capacity of 500 messages", cb);
      };

      // Generate message ID
      let messageId = ToolContext.nextMessageId(context.messageCounter);
      let timestamp = ToolContext.now();

      // Encrypt the body using vetKD IBE (keyed to recipient's principal)
      let ciphertext = if (context.encryptionEnabled()) {
        let derivedKey = await Encryption.deriveKeyForPrincipal(recipient, context.vetKdKeyId);
        Encryption.encrypt(body, messageId, derivedKey);
      } else {
        // Fallback: store as plaintext blob (for local testing without vetKD)
        Text.encodeUtf8(body);
      };

      // Store in recipient's inbox
      ToolContext.appendMessage(context.inbox, recipient, {
        id = messageId;
        sender = sender;
        recipient = recipient;
        subject = subject;
        ciphertext = ciphertext;
        timestamp = timestamp;
        read = false;
      });

      ToolContext.makeSuccess(
        Json.obj([
          ("message_id", Json.str(messageId)),
          ("sender", Json.str(Principal.toText(sender))),
          ("recipient", Json.str(Principal.toText(recipient))),
          ("subject", Json.str(subject)),
          ("timestamp", #number(#int(timestamp))),
        ]),
        cb,
      );
    };
  };
};

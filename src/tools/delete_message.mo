import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";

import ToolContext "ToolContext";

module {

  public func config() : McpTypes.Tool = {
    name = "delete_message";
    title = ?"Delete Message";
    description = ?"Delete a message from your inbox. Only the recipient can delete messages. Idempotent — deleting a non-existent message returns deleted: false.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("message_id", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("The message ID to delete")),
        ])),
      ])),
      ("required", Json.arr([Json.str("message_id")])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("message_id", Json.obj([("type", Json.str("string"))])),
        ("deleted", Json.obj([("type", Json.str("boolean"))])),
      ])),
      ("required", Json.arr([Json.str("message_id"), Json.str("deleted")])),
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
      var i : Nat = 0;
      for (msg in msgs.vals()) {
        if (msg.id == messageId) {
          foundIdx := ?i;
        };
        i += 1;
      };

      switch (foundIdx) {
        case (?idx) {
          let newMsgs = ToolContext.removeMessage(msgs, idx);
          ToolContext.setMessages(context.inbox, caller, newMsgs);
          ToolContext.makeSuccess(
            Json.obj([
              ("message_id", Json.str(messageId)),
              ("deleted", Json.bool(true)),
            ]),
            cb,
          );
        };
        case (null) {
          // Not found — idempotent
          ToolContext.makeSuccess(
            Json.obj([
              ("message_id", Json.str(messageId)),
              ("deleted", Json.bool(false)),
            ]),
            cb,
          );
        };
      };
    };
  };
};

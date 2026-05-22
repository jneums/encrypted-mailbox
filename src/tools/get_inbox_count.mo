import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";

import ToolContext "ToolContext";

module {

  public func config() : McpTypes.Tool = {
    name = "get_inbox_count";
    title = ?"Get Inbox Count";
    description = ?"Get a quick summary of your inbox — total message count and unread count. No message data is returned.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("total", Json.obj([("type", Json.str("number"))])),
        ("unread", Json.obj([("type", Json.str("number"))])),
      ])),
      ("required", Json.arr([Json.str("total"), Json.str("unread")])),
    ]);
  };

  public func handle(context : ToolContext.ToolContext) : McpTypes.ToolFn {
    func(_args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {

      let caller = switch (ToolContext.requireAuth(auth, cb)) {
        case (?p) { p };
        case (null) { return };
      };

      let total = ToolContext.inboxSize(context.inbox, caller);
      let unread = ToolContext.unreadCount(context.inbox, caller);

      ToolContext.makeSuccess(
        Json.obj([
          ("total", #number(#int(total))),
          ("unread", #number(#int(unread))),
        ]),
        cb,
      );
    };
  };
};

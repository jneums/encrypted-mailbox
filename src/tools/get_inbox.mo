import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import Buffer "mo:base/Buffer";

import ToolContext "ToolContext";

module {

  public func config() : McpTypes.Tool = {
    name = "get_inbox";
    title = ?"Get Inbox";
    description = ?"List messages in your inbox with metadata (sender, subject, timestamp, read status). Message bodies are NOT returned — use read_message to decrypt and read a specific message.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("limit", Json.obj([
          ("type", Json.str("number")),
          ("description", Json.str("Max results to return (default: 20, max: 100)")),
        ])),
        ("offset", Json.obj([
          ("type", Json.str("number")),
          ("description", Json.str("Number of results to skip (default: 0)")),
        ])),
        ("unread_only", Json.obj([
          ("type", Json.str("boolean")),
          ("description", Json.str("If true, only return unread messages (default: false)")),
        ])),
      ])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("messages", Json.obj([
          ("type", Json.str("array")),
          ("items", Json.obj([
            ("type", Json.str("object")),
            ("properties", Json.obj([
              ("message_id", Json.obj([("type", Json.str("string"))])),
              ("sender", Json.obj([("type", Json.str("string"))])),
              ("subject", Json.obj([("type", Json.str("string"))])),
              ("timestamp", Json.obj([("type", Json.str("number"))])),
              ("read", Json.obj([("type", Json.str("boolean"))])),
            ])),
          ])),
        ])),
        ("total", Json.obj([("type", Json.str("number"))])),
        ("unread", Json.obj([("type", Json.str("number"))])),
      ])),
      ("required", Json.arr([Json.str("messages"), Json.str("total"), Json.str("unread")])),
    ]);
  };

  public func handle(context : ToolContext.ToolContext) : McpTypes.ToolFn {
    func(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {

      let caller = switch (ToolContext.requireAuth(auth, cb)) {
        case (?p) { p };
        case (null) { return };
      };

      // Parse limit
      let limit = switch (Result.toOption(Json.getAsNat(args, "limit"))) {
        case (?n) { if (n > 100) { 100 } else if (n == 0) { 20 } else { n } };
        case (null) { 20 };
      };

      // Parse offset
      let offset = switch (Result.toOption(Json.getAsNat(args, "offset"))) {
        case (?n) { n };
        case (null) { 0 };
      };

      // Parse unread_only
      let unreadOnly = switch (Result.toOption(Json.getAsBool(args, "unread_only"))) {
        case (?b) { b };
        case (null) { false };
      };

      // Get inbox messages, sorted newest first
      let msgs = ToolContext.getMessages(context.inbox, caller);
      let sorted = ToolContext.sortedMessages(msgs);

      // Filter and paginate
      let resultBuf = Buffer.Buffer<Json.Json>(Nat.min(limit, sorted.size()));
      var totalMatching : Nat = 0;
      var totalUnread : Nat = 0;
      var emitted : Nat = 0;

      for (msg in sorted.vals()) {
        if (not msg.read) { totalUnread += 1 };

        let matches = if (unreadOnly) { not msg.read } else { true };
        if (matches) {
          totalMatching += 1;
          if (totalMatching > offset and emitted < limit) {
            resultBuf.add(
              Json.obj([
                ("message_id", Json.str(msg.id)),
                ("sender", Json.str(Principal.toText(msg.sender))),
                ("subject", Json.str(msg.subject)),
                ("timestamp", #number(#int(msg.timestamp))),
                ("read", Json.bool(msg.read)),
              ])
            );
            emitted += 1;
          };
        };
      };

      ToolContext.makeSuccess(
        Json.obj([
          ("messages", Json.arr(Buffer.toArray(resultBuf))),
          ("total", #number(#int(totalMatching))),
          ("unread", #number(#int(totalUnread))),
        ]),
        cb,
      );
    };
  };
};

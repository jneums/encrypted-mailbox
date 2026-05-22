import Result "mo:base/Result";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import Option "mo:base/Option";
import Int "mo:base/Int";
import Time "mo:base/Time";
import HttpTypes "mo:http-types";
import Map "mo:map/Map";

import AuthCleanup "mo:mcp-motoko-sdk/auth/Cleanup";
import AuthState "mo:mcp-motoko-sdk/auth/State";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";

import Mcp "mo:mcp-motoko-sdk/mcp/Mcp";
import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import HttpHandler "mo:mcp-motoko-sdk/mcp/HttpHandler";
import Cleanup "mo:mcp-motoko-sdk/mcp/Cleanup";
import State "mo:mcp-motoko-sdk/mcp/State";
import Payments "mo:mcp-motoko-sdk/mcp/Payments";
import HttpAssets "mo:mcp-motoko-sdk/mcp/HttpAssets";
import Beacon "mo:mcp-motoko-sdk/mcp/Beacon";
import ApiKey "mo:mcp-motoko-sdk/auth/ApiKey";
import IC "mo:ic";

import SrvTypes "mo:mcp-motoko-sdk/server/Types";

// Import tool modules
import ToolContext "tools/ToolContext";
import SendMessage "tools/send_message";
import GetInbox "tools/get_inbox";
import ReadMessage "tools/read_message";
import DeleteMessage "tools/delete_message";
import GetInboxCount "tools/get_inbox_count";

shared ({ caller = deployer }) persistent actor class McpServer(
  args : ?{
    owner : ?Principal;
  }
) = self {

  // The canister owner
  var owner : Principal = Option.get(do ? { args!.owner! }, deployer);

  // State for certified HTTP assets
  var stable_http_assets : HttpAssets.StableEntries = [];
  transient let http_assets = HttpAssets.init(stable_http_assets);

  // Resource contents
  var resourceContents = [
    ("file:///README.md", "# Encrypted Mailbox MCP Server\nA dead-drop encrypted messaging service using vetKey IBE on the Internet Computer."),
  ];

  var appContext : McpTypes.AppContext = State.init(resourceContents);

  // =================================================================================
  // --- MAILBOX STORAGE ---
  // Per-principal inbox using orthogonal persistence
  // =================================================================================
  var inbox : ToolContext.InboxStore = Map.new<Principal, [ToolContext.Message]>();
  var messageCounter : { var count : Nat } = { var count = 0 };

  // =================================================================================
  // --- AUTHENTICATION (ENABLED) ---
  // All tools require authentication
  // =================================================================================

  let issuerUrl = "https://bfggx-7yaaa-aaaai-q32gq-cai.icp0.io";
  let allowanceUrl = "https://prometheusprotocol.org/connections";
  let requiredScopes = ["openid"];

  public query func transformJwksResponse({
    context = _ : Blob;
    response : IC.HttpRequestResult;
  }) : async IC.HttpRequestResult {
    {
      response with headers = [];
    };
  };

  transient let authContext : ?AuthTypes.AuthContext = ?AuthState.init(
    Principal.fromActor(self),
    owner,
    issuerUrl,
    requiredScopes,
    transformJwksResponse,
  );

  // =================================================================================
  // --- BEACON (ENABLED) ---
  // =================================================================================

  let beaconCanisterId = Principal.fromText("m63pw-fqaaa-aaaai-q33pa-cai");
  transient let beaconContext : ?Beacon.BeaconContext = ?Beacon.init(
    beaconCanisterId,
    ?(15 * 60),
  );

  // --- Timers ---
  Cleanup.startCleanupTimer<system>(appContext);

  switch (authContext) {
    case (?ctx) { AuthCleanup.startCleanupTimer<system>(ctx) };
    case (null) { Debug.print("Authentication is disabled.") };
  };

  switch (beaconContext) {
    case (?ctx) { Beacon.startTimer<system>(ctx) };
    case (null) { Debug.print("Beacon is disabled.") };
  };

  // --- RESOURCES ---
  transient let resources : [McpTypes.Resource] = [
    {
      uri = "file:///README.md";
      name = "README.md";
      title = ?"Encrypted Mailbox Documentation";
      description = ?"Overview of the Encrypted Mailbox MCP server";
      mimeType = ?"text/markdown";
    },
  ];

  // --- VetKD Key Configuration ---
  let vetKdKeyId : {
    curve : { #bls12_381_g2 };
    name : Text;
  } = { curve = #bls12_381_g2; name = "key_1" };

  // Encryption at rest via vetKD — enabled by default on mainnet
  var encryptionEnabled : Bool = true;

  // --- TOOL CONTEXT ---
  transient let toolContext : ToolContext.ToolContext = {
    canisterPrincipal = Principal.fromActor(self);
    owner = owner;
    appContext = appContext;
    inbox = inbox;
    messageCounter = messageCounter;
    vetKdKeyId = vetKdKeyId;
    encryptionEnabled = func() : Bool { encryptionEnabled };
  };

  // --- TOOLS ---
  transient let tools : [McpTypes.Tool] = [
    SendMessage.config(),
    GetInbox.config(),
    ReadMessage.config(),
    DeleteMessage.config(),
    GetInboxCount.config(),
  ];

  // --- MCP CONFIG ---
  transient let mcpConfig : McpTypes.McpConfig = {
    self = Principal.fromActor(self);
    allowanceUrl = ?allowanceUrl;
    serverInfo = {
      name = "encrypted-mailbox";
      title = "Encrypted Mailbox";
      version = "0.1.0";
    };
    resources = resources;
    resourceReader = func(uri) {
      Map.get(appContext.resourceContents, Map.thash, uri);
    };
    tools = tools;
    toolImplementations = [
      ("send_message", SendMessage.handle(toolContext)),
      ("get_inbox", GetInbox.handle(toolContext)),
      ("read_message", ReadMessage.handle(toolContext)),
      ("delete_message", DeleteMessage.handle(toolContext)),
      ("get_inbox_count", GetInboxCount.handle(toolContext)),
    ];
    beacon = beaconContext;
  };

  transient let mcpServer = Mcp.createServer(mcpConfig);

  // --- PUBLIC ENTRY POINTS ---

  public query func get_owner() : async Principal { return owner };

  /// Enable or disable vetKD encryption at rest. Only the owner can call this.
  public shared ({ caller }) func set_encryption_enabled(enabled : Bool) : async () {
    if (caller != owner) { Debug.trap("Only the owner can change encryption settings") };
    encryptionEnabled := enabled;
  };

  /// Check if vetKD encryption at rest is enabled.
  public query func get_encryption_enabled() : async Bool { encryptionEnabled };

  public shared ({ caller }) func set_owner(new_owner : Principal) : async Result.Result<(), Payments.TreasuryError> {
    if (caller != owner) { return #err(#NotOwner) };
    owner := new_owner;
    return #ok(());
  };

  public shared func get_treasury_balance(ledger_id : Principal) : async Nat {
    return await Payments.get_treasury_balance(Principal.fromActor(self), ledger_id);
  };

  public shared ({ caller }) func withdraw(
    ledger_id : Principal,
    amount : Nat,
    destination : Payments.Destination,
  ) : async Result.Result<Nat, Payments.TreasuryError> {
    return await Payments.withdraw(
      caller,
      owner,
      ledger_id,
      amount,
      destination,
    );
  };

  // Helper to create the HTTP context for each request.
  private func _create_http_context() : HttpHandler.Context {
    return {
      self = Principal.fromActor(self);
      active_streams = appContext.activeStreams;
      mcp_server = mcpServer;
      streaming_callback = http_request_streaming_callback;
      auth = authContext;
      http_asset_cache = ?http_assets.cache;
      mcp_path = ?"/mcp";
    };
  };

  public query func http_request(req : SrvTypes.HttpRequest) : async SrvTypes.HttpResponse {
    let ctx : HttpHandler.Context = _create_http_context();
    switch (HttpHandler.http_request(ctx, req)) {
      case (?mcpResponse) {
        return mcpResponse;
      };
      case (null) {
        if (req.url == "/") {
          return {
            status_code = 200;
            headers = [("Content-Type", "text/html")];
            body = Text.encodeUtf8("<h1>📬 Encrypted Mailbox</h1><p>A dead-drop encrypted messaging service using vetKey IBE on the Internet Computer.</p><p>Connect via MCP at <code>/mcp</code></p>");
            upgrade = null;
            streaming_strategy = null;
          };
        } else {
          return {
            status_code = 404;
            headers = [];
            body = Blob.fromArray([]);
            upgrade = null;
            streaming_strategy = null;
          };
        };
      };
    };
  };

  public shared func http_request_update(req : SrvTypes.HttpRequest) : async SrvTypes.HttpResponse {
    let ctx : HttpHandler.Context = _create_http_context();
    let mcpResponse = await HttpHandler.http_request_update(ctx, req);
    switch (mcpResponse) {
      case (?res) {
        return res;
      };
      case (null) {
        return {
          status_code = 404;
          headers = [];
          body = Blob.fromArray([]);
          upgrade = null;
          streaming_strategy = null;
        };
      };
    };
  };

  public query func http_request_streaming_callback(token : HttpTypes.StreamingToken) : async ?HttpTypes.StreamingCallbackResponse {
    let ctx : HttpHandler.Context = _create_http_context();
    return HttpHandler.http_request_streaming_callback(ctx, token);
  };

  // --- CANISTER LIFECYCLE MANAGEMENT ---

  system func preupgrade() {
    stable_http_assets := HttpAssets.preupgrade(http_assets);
  };

  system func postupgrade() {
    HttpAssets.postupgrade(http_assets);
  };

  public shared (msg) func create_my_api_key(name : Text, scopes : [Text]) : async Text {
    switch (authContext) {
      case (null) {
        Debug.trap("Authentication is not enabled on this canister.");
      };
      case (?ctx) {
        return await ApiKey.create_my_api_key(
          ctx,
          msg.caller,
          name,
          scopes,
        );
      };
    };
  };

  public shared (msg) func revoke_my_api_key(key_id : Text) : async () {
    switch (authContext) {
      case (null) {
        Debug.trap("Authentication is not enabled on this canister.");
      };
      case (?ctx) {
        return ApiKey.revoke_my_api_key(ctx, msg.caller, key_id);
      };
    };
  };

  public query (msg) func list_my_api_keys() : async [AuthTypes.ApiKeyMetadata] {
    switch (authContext) {
      case (null) {
        Debug.trap("Authentication is not enabled on this canister.");
      };
      case (?ctx) {
        return ApiKey.list_my_api_keys(ctx, msg.caller);
      };
    };
  };

  public type UpgradeFinishedResult = {
    #InProgress : Nat;
    #Failed : (Nat, Text);
    #Success : Nat;
  };
  private func natNow() : Nat {
    return Int.abs(Time.now());
  };
  public func icrc120_upgrade_finished() : async UpgradeFinishedResult {
    #Success(natNow());
  };
};

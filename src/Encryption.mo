import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import Debug "mo:base/Debug";

import NaCl "mo:tweetnacl";

module Encryption {

  // ========== VetKD Types ==========

  public type VetKdCurve = { #bls12_381_g2 };

  public type VetKdKeyId = {
    curve : VetKdCurve;
    name : Text;
  };

  type VetkdSystemApi = actor {
    vetkd_public_key : ({
      canister_id : ?Principal;
      context : Blob;
      key_id : VetKdKeyId;
    }) -> async ({ public_key : Blob });
    vetkd_derive_key : ({
      context : Blob;
      input : Blob;
      key_id : VetKdKeyId;
      transport_public_key : Blob;
    }) -> async ({ encrypted_key : Blob });
  };

  let managementCanister : VetkdSystemApi = actor "aaaaa-aa";

  // Domain separator for this application
  func getContext() : Blob { Text.encodeUtf8("encrypted_mailbox_v1") };

  // G1 point at infinity — using this as transport key returns the raw (unencrypted) vetKey
  func getPointAtInfinity() : Blob {
    Blob.fromArray([
      192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
  };

  let KEY_MATERIAL_SIZE : Nat = 32; // 32 bytes for secretbox key
  let NONCE_SIZE : Nat = 24;        // secretbox nonce

  // ========== Key Derivation ==========

  /// Derive a 32-byte symmetric encryption key for a given principal (the recipient).
  /// Uses vetKD with the point at infinity to get raw key material.
  public func deriveKeyForPrincipal(principal : Principal, keyId : VetKdKeyId) : async [Nat8] {
    let response = await (with cycles = 26_153_846_153) managementCanister.vetkd_derive_key({
      context = getContext();
      input = Principal.toBlob(principal);
      key_id = keyId;
      transport_public_key = getPointAtInfinity();
    });

    let keyBytes = Blob.toArray(response.encrypted_key);
    if (keyBytes.size() < KEY_MATERIAL_SIZE) {
      Debug.trap("VetKD response too short: " # Nat.toText(keyBytes.size()));
    };

    // Take the last 32 bytes as the symmetric key
    let offset : Nat = keyBytes.size() - KEY_MATERIAL_SIZE;
    Array.tabulate<Nat8>(KEY_MATERIAL_SIZE, func(i : Nat) : Nat8 {
      keyBytes[offset + i];
    });
  };

  // ========== Nonce Generation ==========

  /// Derive a deterministic nonce from the message ID.
  /// XOR-folds the message ID bytes into a 24-byte nonce.
  /// Safe because the encryption key is unique per recipient principal,
  /// and each message ID is unique (monotonic counter).
  func deriveNonce(messageId : Text) : [Nat8] {
    let idBytes = Blob.toArray(Text.encodeUtf8(messageId));
    let nonce = Array.init<Nat8>(NONCE_SIZE, 0);
    for (i in idBytes.keys()) {
      let idx = i % NONCE_SIZE;
      nonce[idx] := nonce[idx] ^ idBytes[i];
    };
    Array.freeze(nonce);
  };

  // ========== Encrypt / Decrypt ==========

  /// Encrypt a plaintext string for a recipient. Returns ciphertext as Blob.
  /// messageId is used to derive a unique nonce.
  public func encrypt(plaintext : Text, messageId : Text, derivedKey : [Nat8]) : Blob {
    let nonce = deriveNonce(messageId);
    let msg = Blob.toArray(Text.encodeUtf8(plaintext));
    let ciphertext = NaCl.BOX.SECRET.box(msg, nonce, derivedKey);
    Blob.fromArray(ciphertext);
  };

  /// Decrypt a ciphertext Blob. Returns plaintext string or null on failure.
  public func decrypt(ciphertext : Blob, messageId : Text, derivedKey : [Nat8]) : ?Text {
    let nonce = deriveNonce(messageId);
    let box = Blob.toArray(ciphertext);
    switch (NaCl.BOX.SECRET.open(box, nonce, derivedKey)) {
      case (?plainBytes) {
        Text.decodeUtf8(Blob.fromArray(plainBytes));
      };
      case (null) { null };
    };
  };
};

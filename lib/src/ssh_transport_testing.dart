part of 'ssh_transport.dart';

/// The state a test puts an [SSHTransport] in, and reads back, without a
/// peer to run a key exchange with. Hidden from `package:dartssh2/dartssh2.dart`;
/// a test imports `package:dartssh2/src/ssh_transport.dart`.
@visibleForTesting
extension SSHTransportTesting on SSHTransport {
  static Uint8List hostkeyFingerprint(Uint8List hostkey) =>
      _hostkeyFingerprint(hostkey);

  /// As if the peer had sent its identification string.
  void receivedVersion(String version) => _remoteVersion = version;

  set kexType(SSHKexType? value) => _kexType = value;
  set clientCipherType(SSHCipherType? value) => _clientCipherType = value;
  set serverCipherType(SSHCipherType? value) => _serverCipherType = value;
  set clientMacType(SSHMacType? value) => _clientMacType = value;
  set serverMacType(SSHMacType? value) => _serverMacType = value;

  set sharedSecret(BigInt? value) => _sharedSecret = value;
  set exchangeHash(Uint8List? value) => _exchangeHash = value;
  set sessionId(Uint8List? value) => _sessionId = value;

  bool get kexInProgress => _kexInProgress;
  set kexInProgress(bool value) => _kexInProgress = value;
  set sentKexInit(bool value) => _sentKexInit = value;

  BlockCipher? get encryptCipher => _encryptCipher;
  BlockCipher? get decryptCipher => _decryptCipher;
  set decryptCipher(BlockCipher? value) => _decryptCipher = value;
  Mac? get localMac => _localMac;
  Mac? get remoteMac => _remoteMac;
  set remoteMac(Mac? value) => _remoteMac = value;

  Uint8List? get localCipherKey => _localCipherKey;
  set localCipherKey(Uint8List? value) => _localCipherKey = value;
  Uint8List? get localIV => _localIV;
  set localIV(Uint8List? value) => _localIV = value;
  Uint8List? get localAeadKey => _localAeadKey;
  Uint8List? get localChaChaEncKey => _localChaChaEncKey;
  Uint8List? get localChaChaLenKey => _localChaChaLenKey;

  Uint8List? get remoteCipherKey => _remoteCipherKey;
  Uint8List? get remoteIV => _remoteIV;
  Uint8List? get remoteAeadKey => _remoteAeadKey;
  set remoteAeadKey(Uint8List? value) => _remoteAeadKey = value;
  Uint8List? get remoteAeadFixedNonce => _remoteAeadFixedNonce;
  set remoteAeadFixedNonce(Uint8List? value) => _remoteAeadFixedNonce = value;
  Uint8List? get remoteChaChaEncKey => _remoteChaChaEncKey;
  Uint8List? get remoteChaChaLenKey => _remoteChaChaLenKey;

  /// Unprocessed bytes from the socket.
  ChunkBuffer get buffer => _buffer;
  List<Uint8List> get rekeyPendingPackets => _rekeyPendingPackets;

  Uint8List nonceForSequence(Uint8List iv, int sequence) =>
      _nonceForSequence(iv, sequence);
  Uint8List? consumeAeadPacket(SSHCipherType cipherType) =>
      _consumeAeadPacket(cipherType);
  void applyLocalKeys() => _applyLocalKeys();
  void applyRemoteKeys() => _applyRemoteKeys();
  Future<void> handleMessageKexInit(Uint8List payload) =>
      _handleMessageKexInit(payload);

  /// What a test playing the server needs to answer the exchange: the
  /// client's identification, its KEXINIT, and its ECDH public key.
  String get localVersion => _localVersion;
  Uint8List? get localKexInit => _localKexInit;
  Uint8List? get kexPublicKey => switch (_kex) {
        final SSHKexECDH kex => kex.publicKey,
        _ => null,
      };
  Future<void> handleMessageKexReply(Uint8List payload) =>
      _handleMessageKexReply(payload);
  Future<void> handleMessageNewKeys() => _handleMessageNewKeys(Uint8List(0));
}

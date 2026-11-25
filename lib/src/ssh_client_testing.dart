part of 'ssh_client.dart';

/// What a test drives an [SSHClient] through without a server. Hidden from
/// `package:dartssh2/dartssh2.dart`; a test imports
/// `package:dartssh2/src/ssh_client.dart`.
@visibleForTesting
extension SSHClientTesting on SSHClient {
  /// The underlying transport, for tests that drive the protocol in memory.
  SSHTransport get transport => _transport;

  /// As if the transport had finished its key exchange.
  void handleTransportReady() => _handleTransportReady();

  /// Delivers a decoded SSH packet payload as if the server had sent it.
  void handlePacket(Uint8List payload) => _handlePacket(payload);
}

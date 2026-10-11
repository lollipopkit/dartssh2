part of 'ssh_client.dart';

/// What a test drives an [SSHClient] through without a server. Hidden from
/// `package:dartssh2/dartssh2.dart`; a test imports
/// `package:dartssh2/src/ssh_client.dart`.
@visibleForTesting
extension SSHClientTesting on SSHClient {
  /// As if the transport had finished its key exchange.
  void handleTransportReady() => _handleTransportReady();
}

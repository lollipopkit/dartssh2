import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/socket/ssh_socket_io.dart'
    if (dart.library.js) 'package:dartssh2/src/socket/ssh_socket_js.dart';

/// An abstraction over a TCP socket connection.
abstract class SSHSocket {
  /// Connects to a host and port, returning a [SSHSocket].
  ///
  /// The [timeout] specifies the duration to wait before
  /// throwing a timeout exception. If not provided, no timeout is applied.
  static Future<SSHSocket> connect(
    String host,
    int port, {
    Duration? timeout,
  }) async {
    return await connectNativeSocket(host, port, timeout: timeout);
  }

  /// Data received from the remote host.
  Stream<Uint8List> get stream;

  /// Write to this sink to send data to the remote host.
  StreamSink<List<int>> get sink;

  /// A future that will complete when the consumer closes, or when an error occurs.
  Future<void> get done;

  /// Closes the socket, returning the same future as [done].
  Future<void> close();

  /// Destroys the socket immediately.
  void destroy();

  /// The remote address of the connection.
  /// 
  /// {@template remoteAddrNullable}
  /// Might be `null` if not available (e.g. for forwarded connections).
  /// {@endtemplate}
  String? get remoteAddress;

  /// The remote port of the connection.
  /// 
  /// {@macro remoteAddrNullable}
  int? get remotePort;
}

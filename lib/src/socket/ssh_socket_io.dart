import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/src/socket/ssh_socket.dart';

Future<SSHSocket> connectNativeSocket(
  String host,
  int port, {
  Duration? timeout,
}) async {
  final socket = await Socket.connect(host, port, timeout: timeout);
  socket.setOption(SocketOption.tcpNoDelay, true);
  return _SSHNativeSocket._(socket);
}

Future<SSHSocket> connectUnixSocket(String path, {Duration? timeout}) async {
  final address = InternetAddress(path, type: InternetAddressType.unix);
  return _SSHNativeSocket._(
    await Socket.connect(address, 0, timeout: timeout),
  );
}

class _SSHNativeSocket implements SSHSocket {
  final Socket _socket;

  _SSHNativeSocket._(this._socket);

  @override
  Stream<Uint8List> get stream => _socket;

  @override
  StreamSink<List<int>> get sink => _socket;

  @override
  Future<void> close() async {
    await _socket.close();
  }

  @override
  Future<void> get done => _socket.done;

  @override
  void destroy() {
    _socket.destroy();
  }

  @override
  Future<void> flush() async {
    await _socket.flush();
  }

  @override
  String toString() {
    final remote = _socket.remoteAddress;
    final address = remote.type == InternetAddressType.unix
        ? remote.address
        : '${remote.host}:${_socket.remotePort}';
    return '_SSHNativeSocket($address)';
  }
}

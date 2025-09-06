import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:dartssh2/src/ssh_channel.dart';

class SSHForwardChannel implements SSHSocket {
  final SSHChannel _channel;
  final String? _originatorIP;
  final int? _originatorPort;

  SSHForwardChannel(
    this._channel, {
    String? originatorIP,
    int? originatorPort,
  })  : _originatorIP = originatorIP,
        _originatorPort = originatorPort {
    _sinkController.stream
        .map((data) => data is Uint8List ? data : Uint8List.fromList(data))
        .map((data) => SSHChannelData(data))
        .pipe(_channel.sink);
  }

  final _sinkController = StreamController<List<int>>();

  /// Data received from the remote host.
  @override
  Stream<Uint8List> get stream => _channel.stream.map((data) => data.bytes);

  /// Write to this sink to send data to the remote host.
  @override
  StreamSink<List<int>> get sink => _sinkController.sink;

  /// Close our end of the channel. Returns a future that waits for the
  /// other side to close.
  @override
  Future<void> close() => _channel.close();

  /// A future that completes when both ends of the channel are closed.
  @override
  Future<void> get done => _channel.done;

  /// Destroys the socket in both directions.
  @override
  void destroy() {
    _channel.destroy();
  }

  @override
  String? get remoteAddress => _originatorIP;
  
  @override
  int? get remotePort => _originatorPort;
}

/// X11 forwarding channel that handles X11 connections from the remote server
class SSHX11Channel implements SSHSocket {
  final SSHChannel _channel;
  final String? _originatorAddress;
  final int? _originatorPort;

  SSHX11Channel(
    this._channel, {
    String? originatorAddress,
    int? originatorPort,
  })  : _originatorAddress = originatorAddress,
        _originatorPort = originatorPort {
    _sinkController.stream
        .map((data) => data is Uint8List ? data : Uint8List.fromList(data))
        .map((data) => SSHChannelData(data))
        .pipe(_channel.sink);
  }

  final _sinkController = StreamController<List<int>>();

  /// Data received from the remote X11 server.
  @override
  Stream<Uint8List> get stream => _channel.stream.map((data) => data.bytes);

  /// Write to this sink to send data to the remote X11 server.
  @override
  StreamSink<List<int>> get sink => _sinkController.sink;

  /// Close our end of the channel. Returns a future that waits for the
  /// other side to close.
  @override
  Future<void> close() => _channel.close();

  /// A future that completes when both ends of the channel are closed.
  @override
  Future<void> get done => _channel.done;

  /// Destroys the socket in both directions.
  @override
  void destroy() {
    _channel.destroy();
  }

  @override
  String? get remoteAddress => _originatorAddress;
  
  @override
  int? get remotePort => _originatorPort;
}
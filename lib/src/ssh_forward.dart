import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:dartssh2/src/ssh_channel.dart';

/// Filters outbound targets requested through a dynamic forward (SOCKS proxy).
///
/// Return `true` to allow connecting to `[host]:[port]`, `false` to deny.
typedef SSHDynamicConnectionFilter = bool Function(String host, int port);

/// Configuration for [SSHClient.forwardDynamic].
class SSHDynamicForwardOptions {
  /// Maximum time allowed to complete the SOCKS5 handshake and target request.
  final Duration handshakeTimeout;

  /// Maximum time allowed to establish the SSH forwarded connection to target.
  final Duration connectTimeout;

  /// Maximum number of simultaneous SOCKS client connections.
  final int maxConnections;

  const SSHDynamicForwardOptions({
    this.handshakeTimeout = const Duration(seconds: 10),
    this.connectTimeout = const Duration(seconds: 15),
    this.maxConnections = 128,
  }) : assert(maxConnections > 0, 'maxConnections must be greater than zero');
}

/// A local dynamic forwarding server (SOCKS5 CONNECT) managed by [SSHClient].
abstract class SSHDynamicForward {
  /// Host/interface the local SOCKS server is bound to.
  String get host;

  /// Bound local port of the SOCKS server.
  int get port;

  /// Whether this forwarder has already been closed.
  bool get isClosed;

  /// Stops accepting new SOCKS connections and closes active ones.
  Future<void> close();
}

class SSHForwardChannel implements SSHSocket {
  final SSHChannel _channel;

  SSHForwardChannel(this._channel) {
    _sinkController.stream.listen(
      (event) {
        if (event is _SSHForwardData) {
          final data = event.data is Uint8List
              ? event.data as Uint8List
              : Uint8List.fromList(event.data);
          _channel.sink.add(SSHChannelData(data));
          return;
        }

        final barrier = event as _SSHForwardFlushBarrier;
        unawaited(_completeFlushBarrier(barrier.completer));
      },
      onError: _channel.sink.addError,
      onDone: _channel.sink.close,
    );
  }

  final _sinkController = StreamController<_SSHForwardUploadEvent>();

  late final StreamSink<List<int>> _sink = _SSHForwardSink(_sinkController);

  /// Data received from the remote host.
  @override
  Stream<Uint8List> get stream => _channel.stream.map((data) => data.bytes);

  /// Write to this sink to send data to the remote host.
  @override
  StreamSink<List<int>> get sink => _sink;

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

  /// Force flush any buffered outgoing data.
  @override
  Future<void> flush() async {
    final barrier = Completer<void>();
    _sinkController.add(_SSHForwardFlushBarrier(barrier));
    await barrier.future;
  }

  Future<void> _completeFlushBarrier(Completer<void> barrier) async {
    try {
      await _channel.flush();
      barrier.complete();
    } catch (error, stackTrace) {
      barrier.completeError(error, stackTrace);
    }
  }
}

sealed class _SSHForwardUploadEvent {}

class _SSHForwardData extends _SSHForwardUploadEvent {
  _SSHForwardData(this.data);

  final List<int> data;
}

class _SSHForwardFlushBarrier extends _SSHForwardUploadEvent {
  _SSHForwardFlushBarrier(this.completer);

  final Completer<void> completer;
}

class _SSHForwardSink implements StreamSink<List<int>> {
  _SSHForwardSink(this._controller);

  final StreamController<_SSHForwardUploadEvent> _controller;

  @override
  void add(List<int> data) {
    _controller.add(_SSHForwardData(data));
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {
    _controller.addError(error, stackTrace);
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final data in stream) {
      add(data);
    }
  }

  @override
  Future<void> close() => _controller.close();

  @override
  Future<void> get done => _controller.done;
}

class SSHX11Channel extends SSHForwardChannel {
  /// Originator address reported by the SSH server for this X11 channel.
  final String originatorIP;

  /// Originator port reported by the SSH server for this X11 channel.
  final int originatorPort;

  SSHX11Channel(
    super.channel, {
    required this.originatorIP,
    required this.originatorPort,
  });
}

import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:test/test.dart';

/// A connection the far end drops: once the transport has closed, nothing a
/// channel does may throw — there is no one to tell but the zone
/// (SERVERBOX-M) — and every channel still ends.
void main() {
  late _DroppableSocket socket;
  late SSHClient client;

  SSHChannelController accept(int id) => client.acceptChannelForTesting(
    localChannelId: id,
    remoteChannelId: id + 100,
    remoteInitialWindowSize: 1024,
    remoteMaximumPacketSize: 1024,
  );

  setUp(() {
    socket = _DroppableSocket();
    client = SSHClient(socket, username: 'demo');
  });

  test('every channel ends when the transport closes', () async {
    final channels = [accept(1), accept(2), accept(3)];

    await socket.drop();

    for (final c in channels) {
      await expectLater(c.channel.done.timeout(const Duration(seconds: 1)), completes);
    }
  });

  test('data in flight when the transport closes is dropped', () async {
    // Written in the same turn as the drop: the upload loop wakes with it
    // after the transport has closed but before the channel is destroyed.
    final errors = <Object>[];
    await runZonedGuarded(() async {
      final channel = accept(1).channel;
      channel.sink.add(SSHChannelData(Uint8List.fromList([1, 2, 3])));
      final dropped = socket.drop();
      channel.sink.add(SSHChannelData(Uint8List.fromList([4, 5, 6])));
      await dropped;
      // Let the upload loop run.
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }, (e, _) => errors.add(e));

    expect(errors, isEmpty);
  });
}

class _DroppableSocket implements SSHSocket {
  final _in = StreamController<Uint8List>();
  final _out = StreamController<List<int>>();

  /// The far end goes away.
  Future<void> drop() async {
    await _in.close();
    // The transport reacts to the end of the stream asynchronously.
    await Future<void>.delayed(Duration.zero);
  }

  @override
  Stream<Uint8List> get stream => _in.stream;

  @override
  StreamSink<List<int>> get sink => _out.sink;

  @override
  Future<void> get done => _in.done;

  @override
  Future<void> close() async {
    if (!_in.isClosed) await _in.close();
    await _out.close();
  }

  @override
  void destroy() {}

  @override
  Future<void> flush() async {}
}

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSH transport version exchange', () {
    test('accepts SSH-1.99 server banner', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      socket.addIncoming('SSH-1.99-OpenSSH_3.6.1p2\r\n');
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-1.99-OpenSSH_3.6.1p2');

      client.close();
    });

    test('rejects non SSH-2 compatible server banners', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      socket.addIncoming('SSH-1.5-OpenSSH_1.2\r\n');

      await expectLater(
        client.authenticated,
        throwsA(
          predicate((error) {
            return error is SSHAuthAbortError &&
                error.reason is SSHHandshakeError;
          }),
        ),
      );

      client.close();
    });

    test('does not busy loop on partial packet after handshake', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      // Complete the version exchange.
      socket.addIncoming('SSH-2.0-OpenSSH_3.6.1p2\r\n');
      await _pumpUntil(() => client.remoteVersion != null);

      // Send the first 4 bytes of a packet indicating a length of 100.
      socket.addRawIncoming(Uint8List.fromList([0, 0, 0, 100]));

      // Wait a moment. If there is a microtask busy loop, the delayed future
      // will never run and the test will timeout.
      await Future<void>.delayed(const Duration(milliseconds: 50));

      client.close();
    });

    test('completes the handshake when the banner is split across two chunks',
        () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      // Regression for T-01: the version line arrives in two TCP segments /
      // WebSocket frames, split in the middle of the identification string.
      socket.addIncoming('SSH-2.0-Open');
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(client.remoteVersion, isNull);

      socket.addIncoming('SSH_9.6\r\n');
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-2.0-OpenSSH_9.6');

      client.close();
    });

    test(
        'completes the handshake when the banner is split across three '
        'chunks, including a split \\r\\n terminator', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      socket.addIncoming('SSH-2.0-Te');
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(client.remoteVersion, isNull);

      socket.addIncoming('st\r');
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(client.remoteVersion, isNull);

      socket.addIncoming('\n');
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-2.0-Test');

      client.close();
    });

    test('accepts a server pre-banner line before the identification line',
        () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      // RFC 4253 §4.2 allows the server to send arbitrary lines of text
      // before its identification line.
      socket.addIncoming('Welcome to our SSH server!\r\n');
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(client.remoteVersion, isNull);

      socket.addIncoming('SSH-2.0-OpenSSH_9.6\r\n');
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-2.0-OpenSSH_9.6');

      client.close();
    });

    test('rejects a server that streams pre-banner lines without end',
        () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      // Each line is short enough that the 10240 byte cap never trips, and
      // the buffer drains as lines are consumed, so only the line counter
      // stops this. Feed it in chunks to exercise the counter surviving
      // across separate _processVersionExchange calls.
      for (var chunk = 0; chunk < 11; chunk++) {
        socket.addIncoming('hi\r\n' * 100);
        await Future<void>.delayed(Duration.zero);
      }

      await expectLater(
        client.authenticated,
        throwsA(
          predicate((error) {
            return error is SSHAuthAbortError &&
                error.reason is SSHHandshakeError;
          }),
        ),
      );

      client.close();
    });

    test('accepts a banner arriving after many pre-banner lines', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      socket.addIncoming('hi\r\n' * 1000);
      socket.addIncoming('SSH-2.0-OpenSSH_9.6\r\n');
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-2.0-OpenSSH_9.6');

      client.close();
    });

    test('rejects an oversized banner that never terminates', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      // No \r or \n anywhere in this data, so the version parser must fall
      // back to the byte cap rather than waiting forever.
      socket.addRawIncoming(Uint8List(10241));

      await expectLater(
        client.authenticated,
        throwsA(
          predicate((error) {
            return error is SSHAuthAbortError &&
                error.reason is SSHHandshakeError;
          }),
        ),
      );

      client.close();
    });

    test('reschedules processing when more data remains in the buffer',
        () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      // Send the version banner followed by some extra data in one go.
      socket.addIncoming('SSH-2.0-OpenSSH_3.6.1p2\r\nSSH-2.0-SecondLine\r\n');

      // Pump until the client processes the first version.
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-2.0-OpenSSH_3.6.1p2');

      client.close();
    });
  });
}

Future<void> _pumpUntil(bool Function() condition) async {
  for (var i = 0; i < 50; i++) {
    if (condition()) {
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  fail('Timed out waiting for condition');
}

class _FakeSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final _sink = _RecordingSink();

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _sink;

  @override
  Future<void> get done => _doneCompleter.future;

  void addIncoming(String data) {
    _inputController.add(Uint8List.fromList(latin1.encode(data)));
  }

  void addRawIncoming(Uint8List data) {
    _inputController.add(data);
  }

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  @override
  void destroy() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_inputController.close());
  }

  @override
  Future<void> flush() async {}
}

class _RecordingSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {
    // SSHTransport writes protocol lines and packets to the sink.
    latin1.decode(data);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final data in stream) {
      add(data);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}

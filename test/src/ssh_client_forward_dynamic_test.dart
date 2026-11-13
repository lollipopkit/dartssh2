import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient.forwardDynamic', () {
    test('waits for authentication before starting', () async {
      final client = SSHClient(
        _FakeSSHSocket(),
        username: 'demo',
        keepAliveInterval: null,
      );

      // This is an intentional unit-test shortcut that bypasses the full SSH
      // handshake. It simulates receiving SSH_Message_Userauth_Success and
      // injects it via client.handlePacket() to drive forwardDynamic's behavior
      // of waiting for authentication. This test only verifies that
      // forwardDynamic properly waits for auth to complete before proceeding.
      scheduleMicrotask(() {
        client.handlePacket(SSH_Message_Userauth_Success().encode());
      });

      final dynamicForward = await client.forwardDynamic(
        bindHost: '127.0.0.1',
        bindPort: 0,
      );

      expect(dynamicForward.port, greaterThan(0));
      expect(dynamicForward.isClosed, isFalse);

      await dynamicForward.close();
      expect(dynamicForward.isClosed, isTrue);

      client.close();
      await client.done;
    });
  });

  group('agent channels', () {
    test('are taken only while a session that asked for one is open', () async {
      var connected = 0;
      final client = SSHClient(
        _FakeSSHSocket(),
        username: 'demo',
        keepAliveInterval: null,
        forwardAgent: () async {
          connected++;
          throw StateError('no agent here');
        },
      );
      client.handlePacket(SSH_Message_Userauth_Success().encode());

      Future<void> settle() async {
        for (var i = 0; i < 5; i++) {
          await Future<void>.delayed(Duration.zero);
        }
      }

      var nextServerChannel = 100;
      Future<void> serverOpensAgentChannel() async {
        client.handlePacket(
          SSH_Message_Channel_Open(
            channelType: 'auth-agent@openssh.com',
            senderChannel: nextServerChannel++,
            initialWindowSize: 1 << 16,
            maximumPacketSize: 1 << 15,
          ).encode(),
        );
        await settle();
      }

      // No session asked: a server opening one anyway gets nothing.
      await serverOpensAgentChannel();
      expect(connected, 0);

      // A session without it changes nothing.
      final plain = client.execute('true');
      await settle();
      client.handlePacket(_confirm(local: 0, remote: 7));
      await settle();
      client.handlePacket(
          SSH_Message_Channel_Success(recipientChannel: 0).encode());
      await plain;
      await serverOpensAgentChannel();
      expect(connected, 0);

      final asking = client.execute('true', forwardAgent: true);
      await settle();
      client.handlePacket(_confirm(local: 1, remote: 8));
      await settle();
      client.handlePacket(
          SSH_Message_Channel_Success(recipientChannel: 1).encode());
      await asking;
      await serverOpensAgentChannel();
      expect(connected, 1);

      // That session over, the agent is no longer the server's to open.
      client.handlePacket(
          SSH_Message_Channel_Close(recipientChannel: 1).encode());
      await settle();
      await serverOpensAgentChannel();
      expect(connected, 1);

      client.close();
    });
  });
}

Uint8List _confirm({required int local, required int remote}) =>
    SSH_Message_Channel_Confirmation(
      recipientChannel: local,
      senderChannel: remote,
      initialWindowSize: 1 << 16,
      maximumPacketSize: 1 << 15,
      data: Uint8List(0),
    ).encode();

class _FakeSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _NoopSink();

  @override
  Future<void> get done => _doneCompleter.future;

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

class _NoopSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final _ in stream) {}
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}

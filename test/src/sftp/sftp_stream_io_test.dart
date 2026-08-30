// Uses test_utils.dart, which imports dart:io.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SftpFileWriter unit tests', () {
    test('done completes with the error when the source stream errors',
        () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final controller = StreamController<Uint8List>();
      final writer = file.write(controller.stream);

      controller.addError(StateError('boom'));
      unawaited(controller.close());

      await expectLater(writer.done, throwsA(isA<StateError>()));

      harness.dispose();
    });

    test(
        'done completes with the error when writing to the remote file '
        'fails', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final writer = file.write(Stream.value(Uint8List.fromList([1, 2, 3])));

      final packet = await harness.nextOutgoingPacket();
      final writePacket = SftpWritePacket.decode(packet);

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: writePacket.requestId,
          code: SftpStatusCode.failure,
          message: 'disk full',
        ),
      );

      await expectLater(writer.done, throwsA(isA<SftpStatusError>()));

      harness.dispose();
    });

    test('a stream error stops further chunks from being processed', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final controller = StreamController<Uint8List>();
      final writer = file.write(controller.stream);

      controller.addError(StateError('boom'));

      await expectLater(writer.done, throwsA(isA<StateError>()));

      // Any further events on the (now-cancelled) subscription must not
      // cause a second completion or an unhandled error.
      controller.add(Uint8List.fromList([1, 2, 3]));
      await controller.close();

      // No outgoing write packet should have been produced, since the
      // subscription was cancelled as soon as the error was seen.
      expect(harness.hasOutgoingPacket, isFalse);

      harness.dispose();
    });

    test('abort after normal completion does not throw', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final writer = file.write(const Stream<Uint8List>.empty());
      await writer.done;

      // Should not throw even though `done` has already completed
      // (regression test for the unguarded double-complete).
      await writer.abort();

      harness.dispose();
    });

    test('calling abort twice does not throw', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final writer = file.write(const Stream<Uint8List>.empty());
      await writer.abort();
      await writer.abort();

      harness.dispose();
    });

    test('abort after a remote write failure does not throw', () async {
      final harness = _SftpTestHarness();
      await harness.completeHandshake();
      final file = SftpFile(harness.client, Uint8List.fromList([1]));

      final writer = file.write(Stream.value(Uint8List.fromList([1, 2, 3])));

      final packet = await harness.nextOutgoingPacket();
      final writePacket = SftpWritePacket.decode(packet);
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: writePacket.requestId,
          code: SftpStatusCode.failure,
          message: 'disk full',
        ),
      );

      await expectLater(writer.done, throwsA(isA<SftpStatusError>()));

      // Should not throw even though `done` already completed with an
      // error.
      await writer.abort();

      harness.dispose();
    });
  });

  group('SftpFileWriter integration tests', () {
    late SSHClient client;

    setUp(() async {
      client = await getTestClient();
    });

    tearDown(() async {
      client.close();
      await client.done;
    });

    /*
    group('SftpFileWriter', () {
      test('can pause & resume', () async {
        final sftp = await client.sftp();

        final dataController = StreamController<Uint8List>(
          onListen: () => print('onListen'),
          onPause: () => print('onPause'),
          onResume: () => print('onResume'),
          onCancel: () => print('onCancel'),
        );
        final dataToUpload = dataController.stream;

        final file = await sftp.open(
          'a.out',
          mode: SftpFileOpenMode.create | SftpFileOpenMode.write,
        );
        final writer = file.write(dataToUpload);

        dataController.add(Uint8List(100));

        await Future.delayed(Duration(milliseconds: 1));
        expect(dataController.isPaused, isFalse);

        dataController.add(Uint8List(100));
        writer.pause();

        await Future.delayed(Duration(milliseconds: 1));
        expect(dataController.isPaused, isTrue);

        dataController.add(Uint8List(100));
        writer.resume();

        await Future.delayed(Duration(milliseconds: 1));
        expect(dataController.isPaused, isFalse);

        await dataController.close();
        await writer.done;
      });

      test('can be awaited', () async {
        final sftp = await client.sftp();
        final file = await sftp.open(
          'a.out',
          mode: SftpFileOpenMode.create | SftpFileOpenMode.write,
        );

        final uploader = file.write(Stream.value(Uint8List(100)));
        await uploader;
        expect(uploader.progress, 100);
      });
    });
     */
  }, tags: ['integration']);
}

class _SftpTestHarness {
  _SftpTestHarness() {
    _controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024 * 1024,
      localInitialWindowSize: 1024 * 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024 * 1024,
      remoteInitialWindowSize: 1024 * 1024,
      sendMessage: _handleOutboundMessage,
    );
    client = SftpClient(_controller.channel);
  }

  late final SSHChannelController _controller;
  late final SftpClient client;

  final _outgoing = StreamController<Uint8List>.broadcast();
  var _disposed = false;
  var _hasOutgoingPacket = false;

  bool get hasOutgoingPacket => _hasOutgoingPacket;

  void _handleOutboundMessage(SSHMessage message) {
    if (message is! SSH_Message_Channel_Data) return;
    final reader = SSHMessageReader(message.data);
    final length = reader.readUint32();
    final payload = reader.readBytes(length);
    _hasOutgoingPacket = true;
    _outgoing.add(payload);
  }

  Future<Uint8List> nextOutgoingPacket() => _outgoing.stream.first;

  Future<void> completeHandshake({Map<String, String>? extensions}) async {
    final init = await nextOutgoingPacket();
    expect(SftpInitPacket.decode(init).version, 3);
    sendResponsePacket(SftpVersionPacket(3, extensions ?? {}));
    await client.handshake;
    // The handshake itself produces an outgoing packet; reset the flag so
    // callers can use [hasOutgoingPacket] to check for *subsequent*
    // traffic only.
    _hasOutgoingPacket = false;
  }

  void sendResponsePacket(SftpPacket packet) {
    final payload = packet.encode();
    final writer = SSHMessageWriter();
    writer.writeUint32(payload.length);
    writer.writeBytes(payload);

    _controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: _controller.localId,
        data: writer.takeBytes(),
      ),
    );
  }

  void dispose() {
    if (_disposed) return;
    _disposed = true;

    unawaited(client.close());
    _controller.destroy();
    _outgoing.close();
  }
}

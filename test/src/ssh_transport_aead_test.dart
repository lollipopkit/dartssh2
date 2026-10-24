import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

void main() {
  group('AES-GCM through a backend (#19)', () {
    tearDown(() => sshCryptoBackend = null);
    const cipherType = SSHCipherType.aes256gcm;

    /// One direction keyed as a key exchange keys it — which is where the
    /// backend is asked, once, rather than per packet.
    SSHTransport keyed(
      _CaptureSSHSocket socket, {
      required bool local,
      void Function(Uint8List)? onPacket,
    }) {
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(cipher: [cipherType]),
        onPacket: onPacket,
      )
        ..receivedVersion('SSH-2.0-test')
        ..kexType = SSHKexType.x25519
        ..sharedSecret = BigInt.from(7)
        ..exchangeHash = Uint8List.fromList(List.filled(32, 1))
        ..sessionId = Uint8List.fromList(List.filled(32, 2))
        ..clientCipherType = cipherType
        ..serverCipherType = cipherType;
      local ? transport.applyLocalKeys() : transport.applyRemoteKeys();
      transport.kexInProgress = false;
      return transport;
    }

    test('what the backend seals, pointycastle opens', () async {
      final backend = _GcmBackend();
      sshCryptoBackend = backend;
      final out = _CaptureSSHSocket();
      final tx = keyed(out, local: true);
      for (final n in [1, 2, 3]) {
        tx.sendPacket(Uint8List.fromList([n, n]));
      }
      // Made once, where the key was derived; every packet sealed through it.
      expect(backend.made, ['aes256-gcm@openssh.com']);
      expect(backend.seals, 3);

      sshCryptoBackend = null;
      final inbound = _CaptureSSHSocket();
      final received = Completer<Uint8List>();
      final rx = SSHTransport(
        inbound,
        algorithms: const SSHAlgorithms(cipher: [cipherType]),
        onPacket: received.complete,
      )
        ..receivedVersion('SSH-2.0-test')
        ..serverCipherType = cipherType
        ..remoteAeadKey = tx.localCipherKey
        ..remoteAeadFixedNonce = tx.localIV;
      // After the identification line: the first of the three packets.
      inbound.addIncomingBytes(out.packets[out.packets.length - 3]);
      expect(await received.future.timeout(const Duration(seconds: 2)), [1, 1]);
      tx.close();
      rx.close();
    });

    test('what pointycastle seals, the backend opens', () async {
      final backend = _GcmBackend();
      sshCryptoBackend = backend;
      final inbound = _CaptureSSHSocket();
      final received = Completer<Uint8List>();
      final rx = keyed(inbound, local: false, onPacket: received.complete);

      sshCryptoBackend = null;
      final out = _CaptureSSHSocket();
      final tx = SSHTransport(
        out,
        algorithms: const SSHAlgorithms(cipher: [cipherType]),
      )
        ..clientCipherType = cipherType
        ..localCipherKey = rx.remoteCipherKey
        ..localIV = rx.remoteIV
        ..kexInProgress = false
        ..sendPacket(Uint8List.fromList([9, 8, 7]));

      inbound.addIncomingBytes(out.packets.last);
      expect(
          await received.future.timeout(const Duration(seconds: 2)), [9, 8, 7]);
      expect(backend.opens, 1);
      tx.close();
      rx.close();
    });

    test('a packet the backend will not open fails authentication', () async {
      sshCryptoBackend = _GcmBackend();
      final inbound = _CaptureSSHSocket();
      final rx = keyed(inbound, local: false);

      sshCryptoBackend = null;
      final out = _CaptureSSHSocket();
      final tx = SSHTransport(
        out,
        algorithms: const SSHAlgorithms(cipher: [cipherType]),
      )
        ..clientCipherType = cipherType
        ..localCipherKey = rx.remoteCipherKey
        ..localIV = rx.remoteIV
        ..kexInProgress = false
        ..sendPacket(Uint8List.fromList([251, 9, 8, 7]));
      final tampered = Uint8List.fromList(out.packets.last);
      tampered[tampered.length - 1] ^= 0x01;

      inbound.addIncomingBytes(tampered);
      await expectLater(
        rx.done,
        throwsA(predicate((e) =>
            e is SSHPacketError &&
            e.toString().contains('AEAD authentication failed'))),
      );
      tx.close();
      rx.close();
    });

    test('a re-key away from GCM lets go of the backend\'s cipher', () {
      final backend = _GcmBackend();
      sshCryptoBackend = backend;
      final tx = keyed(_CaptureSSHSocket(), local: true)
        ..sendPacket(Uint8List.fromList([1]));
      expect(backend.seals, 1);

      tx
        ..clientCipherType = SSHCipherType.aes256ctr
        ..clientMacType = SSHMacType.hmacSha256
        ..applyLocalKeys()
        ..sendPacket(Uint8List.fromList([2]));
      expect(backend.seals, 1);
      tx.close();
    });
  });

  group('SSHTransport AEAD', () {
    test('exchanges packets with AES-GCM', () async {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final key = Uint8List(cipherType.keySize);
        final iv = Uint8List(cipherType.ivSize);
        for (var i = 0; i < key.length; i++) {
          key[i] = i;
        }
        for (var i = 0; i < iv.length; i++) {
          iv[i] = i + 16;
        }

        for (final payloadLength in [1, 5, 6, 10, 11, 15, 16, 20, 31, 32]) {
          final senderSocket = _CaptureSSHSocket();
          final sender = SSHTransport(
            senderSocket,
            algorithms: SSHAlgorithms(
              cipher: [cipherType],
            ),
          );

          sender.clientCipherType = cipherType;
          sender.localCipherKey = key;
          sender.localIV = iv;
          sender.kexInProgress = false;

          final payload = Uint8List.fromList(
            List.generate(payloadLength, (index) => index % 256),
          );
          sender.sendPacket(payload);

          final encryptedPacket = senderSocket.packets.last;

          final receiverSocket = _CaptureSSHSocket();
          final receivedPacket = Completer<Uint8List>();
          final receiver = SSHTransport(
            receiverSocket,
            algorithms: SSHAlgorithms(
              cipher: [cipherType],
            ),
            onPacket: (packet) {
              if (!receivedPacket.isCompleted) {
                receivedPacket.complete(packet);
              }
            },
          );

          receiver.receivedVersion('SSH-2.0-test');
          receiver.serverCipherType = cipherType;
          receiver.remoteAeadKey = key;
          receiver.remoteAeadFixedNonce = iv;

          receiverSocket.addIncomingBytes(encryptedPacket);

          final received =
              await receivedPacket.future.timeout(const Duration(seconds: 2));
          expect(received, payload);

          sender.close();
          receiver.close();
        }
      }
    });

    test('accepts channel data message larger than channel payload', () async {
      final key = Uint8List(16);
      final iv = Uint8List(12);
      for (var i = 0; i < key.length; i++) {
        key[i] = i;
      }
      for (var i = 0; i < iv.length; i++) {
        iv[i] = i + 16;
      }

      final senderSocket = _CaptureSSHSocket();
      final sender = SSHTransport(
        senderSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
      );

      sender.clientCipherType = SSHCipherType.aes128gcm;
      sender.localCipherKey = key;
      sender.localIV = iv;
      sender.kexInProgress = false;

      final writer = SSHMessageWriter();
      writer.writeUint8(94); // SSH_MSG_CHANNEL_DATA.
      writer.writeUint32(0); // recipient channel id.
      writer.writeString(Uint8List(32768));
      final payload = writer.takeBytes();
      expect(payload.length, 32777);
      sender.sendPacket(payload);

      final encryptedPacket = senderSocket.packets.last;

      final receiverSocket = _CaptureSSHSocket();
      final receivedPacket = Completer<Uint8List>();
      final receiver = SSHTransport(
        receiverSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
        onPacket: (packet) {
          if (!receivedPacket.isCompleted) {
            receivedPacket.complete(packet);
          }
        },
      );

      receiver.receivedVersion('SSH-2.0-test');
      receiver.serverCipherType = SSHCipherType.aes128gcm;
      receiver.remoteAeadKey = key;
      receiver.remoteAeadFixedNonce = iv;

      receiverSocket.addIncomingBytes(encryptedPacket);

      final received =
          await receivedPacket.future.timeout(const Duration(seconds: 2));
      expect(received, payload);

      sender.close();
      receiver.close();
    });

    test('reports AEAD authentication failure when packet is tampered',
        () async {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final key = Uint8List(cipherType.keySize);
        final iv = Uint8List(cipherType.ivSize);
        for (var i = 0; i < key.length; i++) {
          key[i] = i;
        }
        for (var i = 0; i < iv.length; i++) {
          iv[i] = i + 16;
        }

        final senderSocket = _CaptureSSHSocket();
        final sender = SSHTransport(
          senderSocket,
          algorithms: SSHAlgorithms(
            cipher: [cipherType],
          ),
        );

        sender.clientCipherType = cipherType;
        sender.localCipherKey = key;
        sender.localIV = iv;
        sender.kexInProgress = false;

        sender.sendPacket(Uint8List.fromList([251, 9, 8, 7]));
        final tampered = Uint8List.fromList(senderSocket.packets.last);
        tampered[tampered.length - 1] ^= 0x01;

        final receiverSocket = _CaptureSSHSocket();
        final receiver = SSHTransport(
          receiverSocket,
          algorithms: SSHAlgorithms(
            cipher: [cipherType],
          ),
        );

        receiver.receivedVersion('SSH-2.0-test');
        receiver.serverCipherType = cipherType;
        receiver.remoteAeadKey = key;
        receiver.remoteAeadFixedNonce = iv;

        receiverSocket.addIncomingBytes(tampered);

        await expectLater(
          receiver.done,
          throwsA(
            predicate(
              (error) =>
                  error is SSHPacketError &&
                  error.toString().contains('AEAD authentication failed'),
            ),
          ),
        );

        sender.close();
        receiver.close();
      }
    });

    test('validates AEAD nonce IV length', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transport.nonceForSequence(Uint8List(8), 0),
        throwsA(isA<ArgumentError>()),
      );

      transport.close();
    });

    test('consumeAeadPacket returns null for incomplete inputs', () {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        transport.receivedVersion('SSH-2.0-test');
        transport.serverCipherType = cipherType;
        transport.remoteAeadKey = Uint8List(cipherType.keySize);
        transport.remoteAeadFixedNonce = Uint8List(cipherType.ivSize);

        final resultNoHeader = transport.consumeAeadPacket(cipherType);
        expect(resultNoHeader, isNull);

        transport.buffer.add(Uint8List.fromList([0, 0, 0, 20, 1, 2, 3]));

        final resultPartial = transport.consumeAeadPacket(cipherType);
        expect(resultPartial, isNull);

        transport.close();
      }
    });

    test('applyLocalKeys keeps AEAD mode without cipher/mac instances', () {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        transport.kexType = SSHKexType.x25519;
        transport.sharedSecret = BigInt.from(1);
        transport.exchangeHash = Uint8List.fromList(List<int>.filled(32, 1));
        transport.sessionId = Uint8List.fromList(List<int>.filled(32, 2));
        transport.clientCipherType = cipherType;

        transport.applyLocalKeys();

        final localKey = transport.localCipherKey;
        final localIv = transport.localIV;
        expect(localKey, isNotNull);
        expect(localKey!.length, cipherType.keySize);
        expect(localIv, isNotNull);
        expect(localIv!.length, cipherType.ivSize);
        expect(transport.encryptCipher, isNull);
        expect(transport.localMac, isNull);

        transport.close();
      }
    });

    test('applyRemoteKeys keeps AEAD mode without cipher/mac instances', () {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        transport.kexType = SSHKexType.x25519;
        transport.sharedSecret = BigInt.from(1);
        transport.exchangeHash = Uint8List.fromList(List<int>.filled(32, 3));
        transport.sessionId = Uint8List.fromList(List<int>.filled(32, 4));
        transport.serverCipherType = cipherType;

        transport.applyRemoteKeys();

        final remoteKey = transport.remoteCipherKey;
        final remoteIv = transport.remoteIV;
        expect(remoteKey, isNotNull);
        expect(remoteKey!.length, cipherType.keySize);
        expect(remoteIv, isNotNull);
        expect(remoteIv!.length, cipherType.ivSize);
        expect(transport.decryptCipher, isNull);
        expect(transport.remoteMac, isNull);

        transport.close();
      }
    });

    test('rekey to ChaCha clears stale GCM cipher state', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.kexType = SSHKexType.x25519;
      transport.sharedSecret = BigInt.from(21);
      transport.exchangeHash = Uint8List.fromList(List<int>.filled(32, 22));
      transport.sessionId = Uint8List.fromList(List<int>.filled(32, 23));

      transport.clientCipherType = SSHCipherType.aes128gcm;
      transport.applyLocalKeys();
      expect(transport.localCipherKey, isNotNull);
      expect(transport.localIV, isNotNull);

      transport.clientCipherType = SSHCipherType.chacha20poly1305;
      transport.applyLocalKeys();
      expect(transport.localCipherKey, isNull);
      expect(transport.localIV, isNull);
      expect(transport.localAeadKey, isNull);
      expect(transport.localChaChaEncKey, isNotNull);
      expect(transport.localChaChaLenKey, isNotNull);

      transport.serverCipherType = SSHCipherType.aes128gcm;
      transport.applyRemoteKeys();
      expect(transport.remoteCipherKey, isNotNull);
      expect(transport.remoteIV, isNotNull);

      transport.serverCipherType = SSHCipherType.chacha20poly1305;
      transport.applyRemoteKeys();
      expect(transport.remoteCipherKey, isNull);
      expect(transport.remoteIV, isNull);
      expect(
        transport.remoteAeadFixedNonce,
        isNull,
      );
      expect(
        transport.remoteChaChaEncKey,
        isNotNull,
      );
      expect(
        transport.remoteChaChaLenKey,
        isNotNull,
      );

      transport.close();
    });

    test('rekey from ChaCha clears stale ChaCha state', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.kexType = SSHKexType.x25519;
      transport.sharedSecret = BigInt.from(31);
      transport.exchangeHash = Uint8List.fromList(List<int>.filled(32, 32));
      transport.sessionId = Uint8List.fromList(List<int>.filled(32, 33));

      transport.clientCipherType = SSHCipherType.chacha20poly1305;
      transport.applyLocalKeys();
      expect(
        transport.localChaChaEncKey,
        isNotNull,
      );
      expect(
        transport.localChaChaLenKey,
        isNotNull,
      );

      transport.clientCipherType = SSHCipherType.aes128gcm;
      transport.applyLocalKeys();
      expect(transport.localChaChaEncKey, isNull);
      expect(transport.localChaChaLenKey, isNull);
      expect(transport.localAeadKey, isNotNull);
      expect(transport.localCipherKey, isNotNull);
      expect(transport.localIV, isNotNull);

      transport.clientCipherType = SSHCipherType.aes128ctr;
      transport.clientMacType = SSHMacType.hmacSha256;
      transport.applyLocalKeys();
      expect(transport.localChaChaEncKey, isNull);
      expect(transport.localChaChaLenKey, isNull);
      expect(transport.localAeadKey, isNull);
      expect(transport.localCipherKey, isNull);
      expect(transport.localIV, isNull);
      expect(transport.encryptCipher, isNotNull);
      expect(transport.localMac, isNotNull);

      transport.serverCipherType = SSHCipherType.chacha20poly1305;
      transport.applyRemoteKeys();
      expect(
        transport.remoteChaChaEncKey,
        isNotNull,
      );
      expect(
        transport.remoteChaChaLenKey,
        isNotNull,
      );

      transport.serverCipherType = SSHCipherType.aes128gcm;
      transport.applyRemoteKeys();
      expect(transport.remoteChaChaEncKey, isNull);
      expect(transport.remoteChaChaLenKey, isNull);
      expect(transport.remoteAeadKey, isNotNull);
      expect(
        transport.remoteAeadFixedNonce,
        isNotNull,
      );
      expect(transport.remoteCipherKey, isNotNull);
      expect(transport.remoteIV, isNotNull);

      transport.serverCipherType = SSHCipherType.aes128ctr;
      transport.serverMacType = SSHMacType.hmacSha256;
      transport.applyRemoteKeys();
      expect(transport.remoteChaChaEncKey, isNull);
      expect(transport.remoteChaChaLenKey, isNull);
      expect(transport.remoteAeadKey, isNull);
      expect(
        transport.remoteAeadFixedNonce,
        isNull,
      );
      expect(transport.remoteCipherKey, isNull);
      expect(transport.remoteIV, isNull);
      expect(transport.decryptCipher, isNotNull);
      expect(transport.remoteMac, isNotNull);

      transport.close();
    });

    test('applyLocalKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.kexType = SSHKexType.x25519;
      transport.sharedSecret = BigInt.from(5);
      transport.exchangeHash = Uint8List.fromList(List<int>.filled(32, 6));
      transport.sessionId = Uint8List.fromList(List<int>.filled(32, 7));
      transport.clientCipherType = SSHCipherType.aes128ctr;
      transport.clientMacType = SSHMacType.hmacSha256;

      transport.applyLocalKeys();

      expect(transport.encryptCipher, isNotNull);
      expect(transport.localMac, isNotNull);

      transport.close();
    });

    test('applyRemoteKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.kexType = SSHKexType.x25519;
      transport.sharedSecret = BigInt.from(8);
      transport.exchangeHash = Uint8List.fromList(List<int>.filled(32, 9));
      transport.sessionId = Uint8List.fromList(List<int>.filled(32, 10));
      transport.serverCipherType = SSHCipherType.aes128ctr;
      transport.serverMacType = SSHMacType.hmacSha256;

      transport.applyRemoteKeys();

      expect(transport.decryptCipher, isNotNull);
      expect(transport.remoteMac, isNotNull);

      transport.close();
    });

    test('kexinit allows missing MAC when AEAD cipher is selected', () async {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(
          socket,
          algorithms: SSHAlgorithms(
            cipher: [cipherType],
            mac: const [SSHMacType.hmacSha256],
          ),
        );

        transport.kexInProgress = true;
        transport.sentKexInit = true;

        final payload = SSH_Message_KexInit(
          kexAlgorithms: [SSHKexType.x25519.name],
          serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
          encryptionClientToServer: [cipherType.name],
          encryptionServerToClient: [cipherType.name],
          macClientToServer: const ['missing-mac'],
          macServerToClient: const ['missing-mac'],
          compressionClientToServer: const ['none'],
          compressionServerToClient: const ['none'],
          firstKexPacketFollows: false,
        ).encode();

        await expectLater(transport.handleMessageKexInit(payload), completes);

        transport.close();
      }
    });

    test('sendPacket buffers non-kex packets during key exchange', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.kexInProgress = true;

      // 94 is outside control/kex message ranges and should be buffered.
      transport.sendPacket(Uint8List.fromList([94, 1, 2]));

      final pending = transport.rekeyPendingPackets;
      expect(pending, hasLength(1));
      expect(pending.first, Uint8List.fromList([94, 1, 2]));

      transport.close();
    });

    test('applyLocalKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transport.applyLocalKeys(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transport.applyRemoteKeys(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyLocalKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.kexType = SSHKexType.x25519;
      transport.sharedSecret = BigInt.from(11);
      transport.exchangeHash = Uint8List.fromList(List<int>.filled(32, 12));
      transport.sessionId = Uint8List.fromList(List<int>.filled(32, 13));
      transport.clientCipherType = SSHCipherType.aes128ctr;

      expect(
        () => transport.applyLocalKeys(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.kexType = SSHKexType.x25519;
      transport.sharedSecret = BigInt.from(14);
      transport.exchangeHash = Uint8List.fromList(List<int>.filled(32, 15));
      transport.sessionId = Uint8List.fromList(List<int>.filled(32, 16));
      transport.serverCipherType = SSHCipherType.aes128ctr;

      expect(
        () => transport.applyRemoteKeys(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('kexinit requires client MAC when non-AEAD cipher is selected',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128ctr],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      transport.kexInProgress = true;
      transport.sentKexInit = true;

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128ctr.name],
        encryptionServerToClient: [SSHCipherType.aes128ctr.name],
        macClientToServer: const ['missing-mac'],
        macServerToClient: [SSHMacType.hmacSha256.name],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      await expectLater(
        transport.handleMessageKexInit(payload),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('kexinit requires server MAC when non-AEAD cipher is selected',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128ctr],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      transport.kexInProgress = true;
      transport.sentKexInit = true;

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128ctr.name],
        encryptionServerToClient: [SSHCipherType.aes128ctr.name],
        macClientToServer: [SSHMacType.hmacSha256.name],
        macServerToClient: const ['missing-mac'],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      await expectLater(
        transport.handleMessageKexInit(payload),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });
  });
}

class _CaptureSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final packets = <Uint8List>[];

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _CaptureSink(packets);

  @override
  Future<void> get done => _doneCompleter.future;

  void addIncomingBytes(Uint8List data) {
    _inputController.add(Uint8List.fromList(data));
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

class _CaptureSink implements StreamSink<List<int>> {
  _CaptureSink(this._packets);

  final List<Uint8List> _packets;

  @override
  void add(List<int> data) {
    _packets.add(Uint8List.fromList(data));
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}

/// A backend whose AES-GCM is pointycastle's, counted: what it seals has to
/// be what the library seals without it.
class _GcmBackend extends SSHCryptoBackend {
  final made = <String>[];
  var seals = 0;
  var opens = 0;

  @override
  SSHAeadCipher? createAead(String algorithm, Uint8List key) {
    made.add(algorithm);
    return _PointycastleGcm(this, key);
  }
}

class _PointycastleGcm implements SSHAeadCipher {
  _PointycastleGcm(this.backend, this.key);

  final _GcmBackend backend;
  final Uint8List key;

  Uint8List _run(bool encrypt, Uint8List nonce, Uint8List aad, Uint8List in_) {
    final cipher = GCMBlockCipher(AESEngine())
      ..init(encrypt, AEADParameters(KeyParameter(key), 128, nonce, aad));
    return cipher.process(in_);
  }

  @override
  Uint8List seal(Uint8List nonce, Uint8List aad, Uint8List plaintext) {
    backend.seals++;
    return _run(true, nonce, aad, plaintext);
  }

  @override
  Uint8List? open(Uint8List nonce, Uint8List aad, Uint8List sealed) {
    backend.opens++;
    try {
      return _run(false, nonce, aad, sealed);
    } on InvalidCipherTextException {
      return null;
    }
  }
}

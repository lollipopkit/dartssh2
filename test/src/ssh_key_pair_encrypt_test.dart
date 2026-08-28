import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

void main() {
  const passphrase = 'correct horse battery staple';
  final sources = {
    'Ed25519': fixture('ssh-ed25519/id_ed25519'),
    'RSA': fixture('ssh-rsa/id_rsa.openssh'),
    'ECDSA P-256': fixture('ecdsa-sha2-nistp256/id_ecdsa'),
  };

  OpenSSHKeyPair parse(String pem) =>
      SSHKeyPair.fromPem(pem).single as OpenSSHKeyPair;

  group('encrypted OpenSSH private-key writing', () {
    for (final source in sources.entries) {
      test('${source.key} round-trips through an encrypted PEM', () {
        final original = parse(source.value);
        final encrypted = original.toPem(passphrase: passphrase);

        expect(SSHKeyPair.isEncryptedPem(encrypted), isTrue);
        final reopened = SSHKeyPair.fromPem(encrypted, passphrase).single;
        expect(
          reopened.toPublicKey().encode(),
          original.toPublicKey().encode(),
        );
      });
    }

    test('uses the OpenSSH cipher, KDF, salt length, and default rounds', () {
      final encrypted = parse(
        sources['Ed25519']!,
      ).toPem(passphrase: passphrase);
      final container =
          OpenSSHKeyPairs.decode(SSHPem.decode(encrypted).content);
      final kdfOptions = container.kdfOptions as OpenSSHBcryptKdfOptions;

      expect(container.cipherName, 'aes256-ctr');
      expect(container.kdfName, 'bcrypt');
      expect(kdfOptions.salt, hasLength(16));
      expect(kdfOptions.rounds, OpenSSHKeyPairs.defaultBcryptRounds);
      expect(container.privateKeyBlob.length % 16, 0);
    });

    test('accepts an explicit positive rounds value', () {
      final encrypted = parse(
        sources['Ed25519']!,
      ).toPem(passphrase: passphrase, rounds: 2);
      final container =
          OpenSSHKeyPairs.decode(SSHPem.decode(encrypted).content);
      final kdfOptions = container.kdfOptions as OpenSSHBcryptKdfOptions;

      expect(kdfOptions.rounds, 2);
      expect(
        SSHKeyPair.fromPem(encrypted, passphrase).single.toPublicKey().encode(),
        parse(sources['Ed25519']!).toPublicKey().encode(),
      );
    });

    test('rejects non-positive rounds', () {
      final key = parse(sources['Ed25519']!);

      expect(
        () => key.toPem(passphrase: passphrase, rounds: 0),
        throwsArgumentError,
      );
      expect(
        () => key.toPem(passphrase: passphrase, rounds: -1),
        throwsArgumentError,
      );
    });

    test('wrong or missing passphrases do not open the key', () {
      final encrypted = parse(
        sources['Ed25519']!,
      ).toPem(passphrase: passphrase, rounds: 2);

      expect(
        () => SSHKeyPair.fromPem(encrypted, 'wrong'),
        throwsA(isA<SSHKeyDecryptError>()),
      );
      expect(
        () => SSHKeyPair.fromPem(encrypted),
        throwsA(isA<SSHKeyDecryptError>()),
      );
    });

    test('an empty passphrase writes the unencrypted form', () {
      final pem = parse(sources['Ed25519']!).toPem(passphrase: '');

      expect(SSHKeyPair.isEncryptedPem(pem), isFalse);
      expect(
        () => OpenSSHKeyPairs.encrypted(
          publicKeys: const [],
          unencryptedPrivateKeyBlob: Uint8List(0),
          passphrase: '',
        ),
        throwsArgumentError,
      );
    });

    test('salt and checkint are fresh for every encrypted encoding', () {
      final key = parse(sources['Ed25519']!);
      final pems = List.generate(
        3,
        (_) => key.toPem(passphrase: passphrase, rounds: 2),
      );

      expect(pems.toSet(), hasLength(pems.length));
    });
  });

  group('ssh-keygen interoperability', () {
    final sshKeygen = _findSshKeygen();

    for (final source in sources.entries) {
      test('ssh-keygen reads the encrypted ${source.key} key', () {
        final original = parse(source.value);
        final directory = Directory.systemTemp.createTempSync('dartssh2-key-');
        addTearDown(() => directory.deleteSync(recursive: true));
        final keyFile = File('${directory.path}${Platform.pathSeparator}id')
          ..writeAsStringSync(original.toPem(passphrase: passphrase));
        _restrictPrivateKeyPermissions(keyFile);

        final result = Process.runSync(sshKeygen!, [
          '-y',
          '-P',
          passphrase,
          '-f',
          keyFile.path,
        ]);
        expect(
          result.exitCode,
          0,
          reason: 'ssh-keygen rejected the key: ${result.stderr}',
        );

        final publicKey = original.toPublicKey().encode();
        final printed = (result.stdout as String).trim().split(RegExp(r'\s+'));
        expect(printed.first, SSHHostKey.getType(publicKey));
        expect(printed[1], base64.encode(publicKey));
      }, skip: sshKeygen == null ? 'ssh-keygen is not available' : null);
    }
  });
}

String? _findSshKeygen() {
  for (final path in const [
    '/usr/bin/ssh-keygen',
    '/bin/ssh-keygen',
    '/usr/local/bin/ssh-keygen',
  ]) {
    if (File(path).existsSync()) return path;
  }

  final result = Process.runSync(
    Platform.isWindows ? 'where.exe' : 'which',
    ['ssh-keygen'],
  );
  if (result.exitCode != 0) return null;

  final firstLine =
      (result.stdout as String).trim().split(RegExp(r'\r?\n')).first;
  return firstLine.isEmpty ? null : firstLine;
}

void _restrictPrivateKeyPermissions(File file) {
  late ProcessResult result;
  if (Platform.isWindows) {
    final username = Platform.environment['USERNAME'];
    if (username == null || username.isEmpty) {
      throw StateError('USERNAME is unavailable');
    }
    result = Process.runSync('icacls.exe', [
      file.path,
      '/inheritance:r',
      '/grant:r',
      '$username:F',
    ]);
  } else {
    result = Process.runSync('chmod', ['600', file.path]);
  }

  expect(
    result.exitCode,
    0,
    reason: 'failed to restrict private-key permissions: ${result.stderr}',
  );
}

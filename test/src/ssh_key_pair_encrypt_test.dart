import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

/// Writing an encrypted `OPENSSH PRIVATE KEY`, which this library could until
/// now only read.
///
/// A round trip through this library proves only that it agrees with itself,
/// so the test that matters is the one at the bottom: `ssh-keygen` reading what
/// we wrote. The format is bcrypt_pbkdf + aes256-ctr and the details it is easy
/// to get wrong — padding to the cipher's block size rather than to 8, the salt
/// and rounds in the kdf options, the key and IV taken from one derived buffer
/// — are all invisible to a round trip.
void main() {
  const passphrase = 'correct horse battery staple';

  /// The fixtures, re-encoded through the encrypting path.
  final sources = {
    'ed25519': fixture('ssh-ed25519/id_ed25519', normalizeNewlines: true),
    'rsa': fixture('ssh-rsa/id_rsa.openssh', normalizeNewlines: true),
    'ecdsa-p256': fixture(
      'ecdsa-sha2-nistp256/id_ecdsa',
      normalizeNewlines: true,
    ),
  };

  OpenSSHKeyPair parse(String pem) =>
      SSHKeyPair.fromPem(pem).single as OpenSSHKeyPair;

  group('round trip', () {
    for (final entry in sources.entries) {
      test('${entry.key} survives being encrypted and opened again', () {
        final original = parse(entry.value);
        final encrypted = original.toPem(passphrase: passphrase);

        expect(SSHKeyPair.isEncryptedPem(encrypted), isTrue);
        expect(
          encrypted,
          isNot(contains(original.toPem().split('\n')[1])),
          reason: 'the body must not be the plain one with a header on it',
        );

        final reopened = parse(
          SSHKeyPair.fromPem(encrypted, passphrase).single.toPem(),
        );
        // Compared as re-encoded plain PEMs rather than byte for byte: the
        // checkint is random, so two encodings of one key differ.
        expect(reopened.toPublicKey().encode(), original.toPublicKey().encode());
      });
    }

    test('the wrong passphrase does not open it', () {
      final encrypted = parse(sources['ed25519']!).toPem(passphrase: 'right');
      expect(
        () => SSHKeyPair.fromPem(encrypted, 'wrong'),
        throwsA(isA<SSHKeyDecryptError>()),
      );
    });

    test('no passphrase at all does not open it', () {
      final encrypted = parse(
        sources['ed25519']!,
      ).toPem(passphrase: passphrase);
      // `SSHKeyDecryptError`, the same as a wrong one: from outside, a key
      // that will not open is a key that will not open.
      expect(
        () => SSHKeyPair.fromPem(encrypted),
        throwsA(isA<SSHKeyDecryptError>()),
      );
    });

    test('an empty passphrase writes the plain form, not an empty-key one', () {
      // Otherwise a caller that passes the user's untouched text field would
      // produce a key encrypted under '', which every tool would open.
      final pem = parse(sources['ed25519']!).toPem(passphrase: '');
      expect(SSHKeyPair.isEncryptedPem(pem), isFalse);
      expect(() => OpenSSHKeyPairs.encrypted(
        publicKeys: const [],
        unencryptedPrivateKeyBlob: Uint8List(0),
        passphrase: '',
      ), throwsArgumentError);
    });
  });

  group('interop', () {
    // Skipped rather than failed where there is no ssh-keygen: this is the
    // only check that the bytes are right, and it must not be quietly dropped
    // on a machine that has one.
    final sshKeygen = _whichSshKeygen();

    for (final entry in sources.entries) {
      test('ssh-keygen reads the ${entry.key} key we wrote', () {
        final original = parse(entry.value);
        final dir = Directory.systemTemp.createTempSync('dartssh2-keygen-');
        addTearDown(() => dir.deleteSync(recursive: true));
        final file = File('${dir.path}/id')
          ..writeAsStringSync(original.toPem(passphrase: passphrase));
        // ssh-keygen refuses a key the rest of the world can read.
        Process.runSync('chmod', ['600', file.path]);

        final result = Process.runSync(sshKeygen!, [
          '-y',
          '-P',
          passphrase,
          '-f',
          file.path,
        ]);
        expect(
          result.exitCode,
          0,
          reason: 'ssh-keygen rejected it: ${result.stderr}',
        );

        // `-y` prints `<type> <base64>`; the comment is not part of it.
        // The blob's own type, not the key pair's: an RSA pair signs as
        // `rsa-sha2-256` while its public key is still `ssh-rsa`, which is
        // what ssh-keygen prints.
        final blob = original.toPublicKey().encode();
        final printed = (result.stdout as String).trim().split(' ');
        expect(printed.first, SSHHostKey.getType(blob));
        expect(
          printed[1],
          base64.encode(blob),
          reason: 'the public key ssh-keygen derived is not the one we hold',
        );
      }, skip: sshKeygen == null ? 'ssh-keygen not on PATH' : null);
    }
  });
}

String? _whichSshKeygen() {
  for (final path in const [
    '/usr/bin/ssh-keygen',
    '/bin/ssh-keygen',
    '/usr/local/bin/ssh-keygen',
  ]) {
    if (File(path).existsSync()) return path;
  }
  final result = Process.runSync(
    Platform.isWindows ? 'where' : 'which',
    ['ssh-keygen'],
  );
  if (result.exitCode != 0) return null;
  final found = (result.stdout as String).trim().split('\n').first.trim();
  return found.isEmpty ? null : found;
}

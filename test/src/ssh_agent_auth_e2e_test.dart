import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

/// `publickey` authentication against a real sshd, with keys a real ssh-agent
/// holds.
///
/// Opt-in: set `DARTSSH2_E2E_HOST`, `DARTSSH2_E2E_USER` (`DARTSSH2_E2E_PORT`
/// for anything but 22) and `DARTSSH2_E2E_AGENT_SOCK`, an agent holding at
/// least one key the account authorises. The account must not authorise the
/// fixture key below. `DARTSSH2_E2E_KEY_FILE`, an unencrypted private key
/// the account authorises, also runs an in-app key through the same probe.
void main() {
  final env = Platform.environment;
  final host = env['DARTSSH2_E2E_HOST'];
  final user = env['DARTSSH2_E2E_USER'];
  final agentSock = env['DARTSSH2_E2E_AGENT_SOCK'];
  final keyFile = env['DARTSSH2_E2E_KEY_FILE'];
  final port = int.tryParse(env['DARTSSH2_E2E_PORT'] ?? '22') ?? 22;
  final missing = host == null || user == null || agentSock == null;

  group('agent authentication', skip: missing ? 'no e2e server' : null, () {
    late SSHAgentClient agent;
    setUp(() async {
      agent = SSHAgentClient(await SSHSocket.connectUnix(agentSock!));
    });
    tearDown(() => agent.close());

    Future<void> authenticate({
      List<SSHKeyPair>? identities,
      List<SSHSigner>? signers,
    }) async {
      final client = SSHClient(
        await SSHSocket.connect(host!, port),
        username: user!,
        identities: identities,
        signers: signers,
        onVerifyHostKey: (_, __) => true,
      );
      try {
        await client.authenticated;
      } finally {
        client.close();
      }
    }

    /// Published, so no real account authorises it.
    final unauthorised = SSHKeyPair.fromPem(
      File('test/fixtures/ssh-ed25519/id_ed25519').readAsStringSync(),
    ).single;

    test('each key the agent holds signs in', () async {
      final keys = await agent.identities();
      expect(keys, isNotEmpty);
      for (final key in keys) {
        await authenticate(signers: [key]);
      }
    });

    test('a key the server turns down is never signed with', () async {
      final turnedDown = _Counting(unauthorised.signer);
      final accepted = (await agent.identities()).map(_Counting.new).toList();

      await authenticate(signers: [turnedDown, ...accepted]);

      expect(turnedDown.signed, 0);
      expect(accepted.first.signed, 1);
      expect(accepted.skip(1).every((k) => k.signed == 0), isTrue);
    });

    test('an in-app key, after one the server turns down', () async {
      final key = SSHKeyPair.fromPem(File(keyFile!).readAsStringSync());

      await authenticate(identities: [unauthorised, ...key]);
    }, skip: keyFile == null ? 'no DARTSSH2_E2E_KEY_FILE' : null);

    test('a signer that fails passes to the next key', () async {
      final key = (await agent.identities()).first;

      await authenticate(signers: [_Failing(key), key]);
    });

    test('a key that fails to sign is named when nothing else works', () async {
      final key = (await agent.identities()).first;

      await expectLater(
        authenticate(signers: [_Failing(key)]),
        throwsA(isA<SSHAuthFailError>().having(
          (e) => e.message,
          'message',
          contains('denied'),
        )),
      );
    });
  });
}

class _Counting implements SSHSigner {
  _Counting(this._inner);

  final SSHSigner _inner;
  var signed = 0;

  @override
  String get type => _inner.type;

  @override
  Uint8List get publicKey => _inner.publicKey;

  @override
  Future<Uint8List> sign(Uint8List data) {
    signed++;
    return _inner.sign(data);
  }
}

class _Failing extends _Counting {
  _Failing(super.inner);

  @override
  Future<Uint8List> sign(Uint8List data) async => throw SSHAgentError('denied');
}

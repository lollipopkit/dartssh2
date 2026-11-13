import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

/// `publickey` authentication against a real sshd, with keys a real ssh-agent
/// holds.
///
/// Opt-in: set `DARTSSH2_E2E_HOST`, `DARTSSH2_E2E_USER` (`DARTSSH2_E2E_PORT`
/// for anything but 22) and `DARTSSH2_E2E_AGENT_SOCK`, an agent of its own
/// whose every key the account authorises. The account must not authorise the
/// fixture key below. `DARTSSH2_E2E_KEY_FILE`, an unencrypted private key
/// the account authorises, also runs an in-app key through the same probe.
///
/// Several tests fail authentication on purpose: from OpenSSH 9.8 the server
/// needs `PerSourcePenalties no`, or it refuses this address for a while.
///
/// Forwarding needs `ssh-add` on the server and `AllowAgentForwarding yes`
/// for the account; `DARTSSH2_E2E_NO_FORWARD_USER`, an account the same keys
/// reach with `AllowAgentForwarding no`, checks a refusal costs nothing else.
/// `DARTSSH2_E2E_CONSTRAINED_COMMENT` names a key added with `ssh-add -h`
/// for this host alone: usable to sign in here, never offered onward.
/// `DARTSSH2_E2E_ELSEWHERE_COMMENT`, one authorised here but added for another
/// host only, and `DARTSSH2_E2E_CONSTRAINED_USER`, an account that authorises
/// the first alone. The agent signs with no constrained key on a connection
/// left unbound, so that account letting the client in shows the binding.
void main() {
  final env = Platform.environment;
  final host = env['DARTSSH2_E2E_HOST'];
  final user = env['DARTSSH2_E2E_USER'];
  final agentSock = env['DARTSSH2_E2E_AGENT_SOCK'];
  final keyFile = env['DARTSSH2_E2E_KEY_FILE'];
  final noForwardUser = env['DARTSSH2_E2E_NO_FORWARD_USER'];
  final constrainedComment = env['DARTSSH2_E2E_CONSTRAINED_COMMENT'];
  final elsewhereComment = env['DARTSSH2_E2E_ELSEWHERE_COMMENT'];
  final constrainedUser = env['DARTSSH2_E2E_CONSTRAINED_USER'];
  final port = int.tryParse(env['DARTSSH2_E2E_PORT'] ?? '22') ?? 22;
  final missing = host == null || user == null || agentSock == null;

  group('agent authentication', skip: missing ? 'no e2e server' : null, () {
    late SSHAgentClient agent;
    setUp(() async {
      agent = SSHAgentClient(await SSHSocket.connectUnix(agentSock!));
    });
    tearDown(() => agent.close());

    /// A connection of the agent's own, as each client needs one.
    Future<SSHAgentClient> ownAgent() async {
      final own = SSHAgentClient(await SSHSocket.connectUnix(agentSock!));
      addTearDown(own.close);
      return own;
    }

    Future<void> authenticate({
      List<SSHKeyPair>? identities,
      List<SSHSigner>? signers,
      SSHAgentClient? identityAgent,
      String? asUser,
    }) async {
      final client = SSHClient(
        await SSHSocket.connect(host!, port),
        username: asUser ?? user!,
        identities: identities,
        signers: signers,
        identityAgent: identityAgent,
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

    /// Keys added with no destination constraint.
    bool free(SSHAgentIdentity key) =>
        key.comment != constrainedComment && key.comment != elsewhereComment;

    test('each key the agent holds for here signs in', () async {
      final keys = await agent.identities();
      expect(keys, isNotEmpty);
      for (var i = 0; i < keys.length; i++) {
        // Offered on their own, unbound: the agent signs with no constrained
        // key there.
        if (!free(keys[i])) continue;
        // A connection of its own for each client, as each `ssh` opens: one
        // bound to two sessions reads to the agent as a path through both.
        final own = SSHAgentClient(await SSHSocket.connectUnix(agentSock!));
        try {
          await authenticate(signers: [(await own.identities())[i]]);
        } finally {
          await own.close();
        }
      }
    });

    test('a key the server turns down is never signed with', () async {
      final turnedDown = _Counting(unauthorised.signer);
      // Offered unbound: only a key with no destination constraint signs.
      final accepted =
          (await agent.identities()).where(free).map(_Counting.new).toList();

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
      final key = (await agent.identities()).firstWhere(free);

      await authenticate(signers: [_Failing(key), key]);
    });

    test('a key that fails to sign is named when nothing else works', () async {
      final key = (await agent.identities()).firstWhere(free);

      await expectLater(
        authenticate(signers: [_Failing(key)]),
        throwsA(isA<SSHAuthFailError>().having(
          (e) => e.message,
          'message',
          contains('denied'),
        )),
      );
    });

    Future<String> runForwarding(String asUser, {bool ask = true}) async {
      final client = SSHClient(
        await SSHSocket.connect(host!, port),
        username: asUser,
        identityAgent: await ownAgent(),
        forwardAgent: () async =>
            SSHAgentClient(await SSHSocket.connectUnix(agentSock!)),
        onVerifyHostKey: (_, __) => true,
      );
      try {
        return utf8.decode(
          await client.run(
            'ssh-add -L 2>&1; echo forwarding-done',
            forwardAgent: ask,
          ),
        );
      } finally {
        client.close();
      }
    }

    String blobOf(SSHAgentIdentity key) => base64.encode(key.publicKey);

    test('the agent is forwarded: the server lists its keys', () async {
      final keys = await agent.identities();
      final unconstrained = keys.where(free).toList();

      final listed = await runForwarding(user!);

      expect(listed, contains('forwarding-done'));
      for (final key in unconstrained) {
        expect(listed, contains(blobOf(key)));
      }
    });

    test('a session that does not ask gets no agent', () async {
      final listed = await runForwarding(user!, ask: false);

      expect(listed, contains('forwarding-done'));
      for (final key in await agent.identities()) {
        expect(listed, isNot(contains(blobOf(key))));
      }
    });

    final constrained = constrainedComment == null ||
            elsewhereComment == null ||
            constrainedUser == null
        ? 'set DARTSSH2_E2E_CONSTRAINED_COMMENT, _ELSEWHERE_COMMENT and '
            '_CONSTRAINED_USER'
        : null;

    test('a key added for this host only signs in here', () async {
      // An account that takes no other key: the agent signs with a
      // constrained one only on a connection bound to this host.
      await authenticate(
        identityAgent: await ownAgent(),
        asUser: constrainedUser,
      );
    }, skip: constrained);

    test(
        'the agent is asked for keys only once bound: one for another host '
        'is not even offered', () async {
      final own = await ownAgent();
      await authenticate(identityAgent: own);

      final offered = (await own.identities()).map((k) => k.comment);
      expect(offered, contains(constrainedComment));
      expect(offered, isNot(contains(elsewhereComment)));
    }, skip: constrained);

    test('a key added for this host only is not offered onward', () async {
      final key = (await agent.identities())
          .singleWhere((k) => k.comment == constrainedComment);

      final listed = await runForwarding(user!);

      expect(listed, contains('forwarding-done'));
      expect(listed, isNot(contains(blobOf(key))));
    }, skip: constrained);

    test('a server that refuses forwarding still runs the command', () async {
      final keys = await agent.identities();

      final listed = await runForwarding(noForwardUser!);

      expect(listed, contains('forwarding-done'));
      for (final key in keys) {
        expect(listed, isNot(contains(blobOf(key))));
      }
    }, skip: noForwardUser == null ? 'no DARTSSH2_E2E_NO_FORWARD_USER' : null);
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

import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

/// The whole sequence, against a real sshd: a key the server rejects, followed
/// by the password that would have worked.
///
/// Opt-in, like the parser's SSH e2e in the app around this fork. Set
/// `DARTSSH2_E2E_HOST`, `DARTSSH2_E2E_USER` and `DARTSSH2_E2E_PASSWORD` (and
/// `DARTSSH2_E2E_PORT` for anything but 22) to run it; without them it skips.
/// The password goes through the environment, never a file in the repo.
///
/// It needs a server with both `PubkeyAuthentication` and
/// `PasswordAuthentication` on, and an account whose `authorized_keys` does
/// *not* contain the fixture key below.
///
/// Why a real server rather than a fake one: the failure this covers turns on
/// what a server puts in `SSH_MSG_USERAUTH_FAILURE` after rejecting a key —
/// OpenSSH keeps listing `publickey`, because it lists what it accepts and not
/// what the client has left to offer. `test.rebex.net`, which the rest of this
/// suite uses, answers `password, keyboard-interactive` only, so it cannot
/// produce the sequence. Standing a fake server up in-process is no help
/// either: this library implements the client half of a key exchange and there
/// is no server half to hand it, and none of the client's authentication state
/// machine can be reached before a key exchange completes.
void main() {
  final host = Platform.environment['DARTSSH2_E2E_HOST'];
  final user = Platform.environment['DARTSSH2_E2E_USER'];
  final password = Platform.environment['DARTSSH2_E2E_PASSWORD'];
  final port = int.tryParse(Platform.environment['DARTSSH2_E2E_PORT'] ?? '22');

  final missing = host == null || user == null || password == null;

  group('a key the server rejects, then the password', () {
    /// A published fixture, so no real account has it authorised. That is what
    /// makes it useful here: the server has to turn it down.
    List<SSHKeyPair> unauthorisedKey() => SSHKeyPair.fromPem(
          File('test/fixtures/ssh-ed25519/id_ed25519').readAsStringSync(),
        );

    Future<SSHClient> connect({
      required List<SSHKeyPair> keys,
      required String withPassword,
    }) async {
      return SSHClient(
        await SSHSocket.connect(host!, port ?? 22),
        username: user!,
        identities: keys,
        onPasswordRequest: () => withPassword,
        onVerifyHostKey: (type, fingerprint) => true,
      );
    }

    test('the password is still reached and works', () async {
      final client = await connect(
        keys: unauthorisedKey(),
        withPassword: password!,
      );
      try {
        await client.authenticated;
      } finally {
        client.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('a wrong password fails as an auth error, not an internal one', () async {
      final client = await connect(
        keys: unauthorisedKey(),
        withPassword: 'definitely-not-the-password',
      );
      try {
        await client.authenticated;
        fail('expected authentication to fail');
      } on SSHAuthFailError {
        // What running out of methods is supposed to look like.
      } on SSHAuthAbortError {
        // Some servers drop the connection instead. Also an auth outcome.
      } catch (e) {
        fail(
          'authentication ended in $e. Before the fix this was '
          'SSHInternalError(Bad state: No element): the client re-queued '
          'publickey with no keys left and popped an empty queue.',
        );
      } finally {
        client.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  },
      skip: missing
          ? 'set DARTSSH2_E2E_HOST/USER/PASSWORD to run against a real sshd'
          : null);
}

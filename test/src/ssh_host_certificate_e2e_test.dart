import 'dart:convert';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

/// A server whose only host key is a certificate
/// (`HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com`).
///
/// Opt-in, like the other e2e tests here: set `DARTSSH2_E2E_CERT_HOST`,
/// `DARTSSH2_E2E_CERT_USER`, `DARTSSH2_E2E_CERT_PASSWORD` (and
/// `DARTSSH2_E2E_CERT_PORT` for anything but 22), and
/// `DARTSSH2_E2E_CERT_FINGERPRINT` to the certified key's fingerprint as
/// `ssh-keygen -lf <host key>.pub` prints it (`SHA256:...`). Without them it
/// skips.
///
/// With `DARTSSH2_E2E_CERT_CA` set to the authority's public key line
/// (`ssh-ed25519 AAAA...`), trusting it is tried too; the certificate has to
/// name the host as `DARTSSH2_E2E_CERT_HOST`.
///
/// A real server because this library has only the client half of a key
/// exchange — see `ssh_auth_key_then_password_e2e_test.dart`.
void main() {
  final env = Platform.environment;
  final host = env['DARTSSH2_E2E_CERT_HOST'];
  final user = env['DARTSSH2_E2E_CERT_USER'];
  final password = env['DARTSSH2_E2E_CERT_PASSWORD'];
  final fingerprint = env['DARTSSH2_E2E_CERT_FINGERPRINT'];
  final port = int.tryParse(env['DARTSSH2_E2E_CERT_PORT'] ?? '22') ?? 22;
  final missing =
      host == null || user == null || password == null || fingerprint == null;

  test(
    'connects, and asks about the certified key as a plain host key',
    () async {
      final asked = <(String, String)>[];
      final client = SSHClient(
        await SSHSocket.connect(host!, port),
        username: user!,
        onPasswordRequest: () => password,
        onVerifyHostKey: (type, fp) {
          asked.add((type, utf8.decode(fp)));
          return true;
        },
      );
      addTearDown(client.close);

      expect(utf8.decode(await client.run('echo ok')).trim(), 'ok');
      expect(asked, [('ssh-ed25519', fingerprint)]);
    },
    skip: missing ? 'DARTSSH2_E2E_CERT_* unset' : false,
  );

  final ca = env['DARTSSH2_E2E_CERT_CA'];

  Future<SSHClient> trusting(
      List<String> principals, List<String> asked) async {
    return SSHClient(
      await SSHSocket.connect(host!, port),
      username: user!,
      onPasswordRequest: () => password,
      onVerifyHostKey: (type, fp) {
        asked.add(type);
        return true;
      },
      hostCertificateTrust: SSHHostCertificateTrust(
        authorities: [base64.decode(ca!.split(' ')[1])],
        principals: principals,
      ),
    );
  }

  test(
    'with its authority trusted, connects without asking',
    () async {
      final asked = <String>[];
      final client = await trusting([host!], asked);
      addTearDown(client.close);
      expect(utf8.decode(await client.run('echo ok')).trim(), 'ok');
      expect(asked, isEmpty);
    },
    skip: missing || ca == null ? 'DARTSSH2_E2E_CERT_* unset' : false,
  );

  test(
    'with its authority trusted, a name it was not issued for is refused',
    () async {
      final asked = <String>[];
      final client = await trusting(['not-this-host.invalid'], asked);
      addTearDown(client.close);
      await expectLater(client.authenticated, throwsA(anything));
      expect(asked, isEmpty);
    },
    skip: missing || ca == null ? 'DARTSSH2_E2E_CERT_* unset' : false,
  );
}

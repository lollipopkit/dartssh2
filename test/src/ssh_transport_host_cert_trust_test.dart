import 'dart:convert';

import 'package:dartssh2/dartssh2.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:test/test.dart';

import 'helpers/test_kex_server.dart';

/// A host certificate signed by an authority the caller trusts, as OpenSSH's
/// `@cert-authority`: verified in full, and then nothing is asked.
void main() {
  final server =
      TestKexServer(hostKeyAlgorithms: ['ssh-ed25519-cert-v01@openssh.com']);
  final ca = SigningKey.generate();
  final host = SigningKey.generate();
  final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

  late List<(String, String)> asked;
  late SSHTransport transport;

  SSHTransport client({SigningKey? trusting, String reachedAs = 'web-01'}) {
    asked = [];
    return transport = TestKexServer.client(
      onVerifyHostKey: (type, fingerprint) {
        asked.add((type, utf8.decode(fingerprint)));
        return true;
      },
      hostCertificateTrust: trusting == null
          ? null
          : SSHHostCertificateTrust(
              authorities: [ed25519PublicKey(trusting)],
              principals: [reachedAs],
            ),
    );
  }

  Matcher refused(String why) => throwsA(isA<SSHHostkeyError>()
      .having((e) => e.message, 'message', contains(why)));

  tearDown(() => transport.close());

  test('signed by a trusted authority, the host is trusted without asking',
      () async {
    client(trusting: ca);
    final cert =
        ed25519HostCertificate(host: host, ca: ca, principals: ['web-01']);
    await server.exchange(transport, signer: host, hostKey: cert);
    expect(asked, isEmpty);
  });

  test('a certificate naming no principals is valid for any host', () async {
    client(trusting: ca);
    final cert = ed25519HostCertificate(host: host, ca: ca);
    await server.exchange(transport, signer: host, hostKey: cert);
    expect(asked, isEmpty);
  });

  test('a wildcard principal covers the host, as OpenSSH reads it', () async {
    client(trusting: ca, reachedAs: 'web.example.com');
    final cert = ed25519HostCertificate(
        host: host, ca: ca, principals: ['*.example.com']);
    await server.exchange(transport, signer: host, hostKey: cert);
    expect(asked, isEmpty);
  });

  test('expired, it refuses the host rather than asking', () async {
    client(trusting: ca);
    final cert = ed25519HostCertificate(
      host: host,
      ca: ca,
      validAfter: now - 7200,
      validBefore: now - 3600,
    );
    await expectLater(
      server.exchange(transport, signer: host, hostKey: cert),
      refused('expired'),
    );
    expect(asked, isEmpty);
  });

  test('issued for another host, it is refused', () async {
    client(trusting: ca);
    final cert =
        ed25519HostCertificate(host: host, ca: ca, principals: ['db-01']);
    await expectLater(
      server.exchange(transport, signer: host, hostKey: cert),
      refused('not valid for web-01'),
    );
  });

  test('a user certificate from a trusted authority is refused', () async {
    client(trusting: ca);
    final cert = ed25519HostCertificate(host: host, ca: ca, certType: 1);
    await expectLater(
      server.exchange(transport, signer: host, hostKey: cert),
      refused('non-host certificate'),
    );
  });

  test('from an authority not trusted, the certified key is asked about',
      () async {
    client(trusting: SigningKey.generate());
    final cert = ed25519HostCertificate(
      host: host,
      ca: ca,
      validBefore: now - 3600, // expired: not looked at, as OpenSSH does not
    );
    await server.exchange(transport, signer: host, hostKey: cert);
    expect(asked, hasLength(1));
    expect(asked.single.$1, 'ssh-ed25519');
  });

  test('a re-key does not check the certificate again', () async {
    client(trusting: ca);
    await server.exchange(
      transport,
      signer: host,
      hostKey: ed25519HostCertificate(host: host, ca: ca),
    );
    // The same key, now behind a certificate that has run out: the session
    // was established, and goes on.
    await server.exchange(
      transport,
      signer: host,
      hostKey: ed25519HostCertificate(
        host: host,
        ca: ca,
        validAfter: now - 7200,
        validBefore: now - 3600,
      ),
    );
    expect(asked, isEmpty);
  });
}

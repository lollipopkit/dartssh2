import 'dart:convert';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:test/test.dart';

import 'helpers/test_kex_server.dart';

/// A host certificate signed by an authority the caller trusts, as OpenSSH's
/// `@cert-authority`: verified in full, and then nothing is asked. One that
/// does not verify is not refused: its key is asked about as a plain one, as
/// OpenSSH retries with the plain key.
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

  /// As a plain host key: the certified key's type and fingerprint, and
  /// nothing trusted.
  void askedAboutPlainKey() {
    expect(asked, hasLength(1));
    expect(asked.single.$1, 'ssh-ed25519');
    expect(
      asked.single.$2,
      utf8.decode(
        SSHTransportTesting.hostkeyFingerprint(ed25519PublicKey(host)),
      ),
    );
  }

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

  test('expired, its key is asked about instead', () async {
    client(trusting: ca);
    final cert = ed25519HostCertificate(
      host: host,
      ca: ca,
      validAfter: now - 7200,
      validBefore: now - 3600,
    );
    await server.exchange(transport, signer: host, hostKey: cert);
    askedAboutPlainKey();
  });

  test('issued for another host, its key is asked about instead', () async {
    client(trusting: ca);
    final cert =
        ed25519HostCertificate(host: host, ca: ca, principals: ['db-01']);
    await server.exchange(transport, signer: host, hostKey: cert);
    askedAboutPlainKey();
  });

  test('a user certificate from a trusted authority is not trusted', () async {
    client(trusting: ca);
    final cert = ed25519HostCertificate(host: host, ca: ca, certType: 1);
    await server.exchange(transport, signer: host, hostKey: cert);
    askedAboutPlainKey();
  });

  test('a tail that will not parse is asked about, not refused', () async {
    client(trusting: ca);
    final cert = ed25519HostCertificate(host: host, ca: ca);
    // The certified key whole, everything after it gone.
    final cut = Uint8List.sublistView(cert, 0, cert.length - 120);
    await server.exchange(transport, signer: host, hostKey: cut);
    askedAboutPlainKey();
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

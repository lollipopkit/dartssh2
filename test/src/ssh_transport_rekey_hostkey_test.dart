import 'package:dartssh2/dartssh2.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:test/test.dart';

import 'helpers/test_kex_server.dart';

/// A re-key brings the host key along again, and it has to be the one the
/// user was asked about.
void main() {
  final server = TestKexServer();
  late SSHTransport transport;
  late int asked;

  setUp(() {
    asked = 0;
    transport = TestKexServer.client(onVerifyHostKey: (type, fingerprint) {
      asked++;
      return true;
    });
  });

  tearDown(() => transport.close());

  test('a re-key with the same host key goes through without asking again',
      () async {
    final hostKey = SigningKey.generate();
    await server.exchange(transport, signer: hostKey);
    expect(asked, 1);

    await server.exchange(transport, signer: hostKey);
    expect(asked, 1);
  });

  test('a re-key with another host key is refused, not asked about', () async {
    await server.exchange(transport, signer: SigningKey.generate());
    expect(asked, 1);

    await expectLater(
      server.exchange(transport, signer: SigningKey.generate()),
      throwsA(isA<SSHHostkeyError>().having(
        (e) => e.message,
        'message',
        contains('changed during re-key'),
      )),
    );
    expect(asked, 1);
  });
}

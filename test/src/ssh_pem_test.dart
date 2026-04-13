import 'package:dartssh2/dartssh2.dart';

import 'package:test/test.dart';
import 'dart:typed_data';

const _openSshPrivateKeyPem = r'''-----BEGIN OPENSSH PRIVATE KEY-----
AA==
-----END OPENSSH PRIVATE KEY-----''';

void main() {
  test('SSHPem.decode works', () {
    final pem = SSHPem.decode(_openSshPrivateKeyPem);

    expect(pem.type, 'OPENSSH PRIVATE KEY');
  });

  test('SSHPem.decode works with crlf not just lf', () {
    final pem = SSHPem.decode(
      '${_openSshPrivateKeyPem.replaceAll('\n', '\r\n')}\r\n',
    );

    expect(pem.type, 'OPENSSH PRIVATE KEY');
  });

  test('SSHPem.decode can parse header', () {
    final pem = SSHPem.decode(r'''-----BEGIN OPENSSH PRIVATE KEY-----
Header1: Value1
Header2: Value2
AA==
-----END OPENSSH PRIVATE KEY-----''');

    expect(pem.headers, {
      'Header1': 'Value1',
      'Header2': 'Value2',
    });
  });

  test('SSHPem.decode throws on invalid PEM', () {
    expect(() => SSHPem.decode(''), throwsA(isA<FormatException>()));
  });

  test('SSHPem.encode rejects non-positive lineLength', () {
    expect(
      () => SSHPem('TEST', {}, Uint8List.fromList([1, 2, 3])).encode(0),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => SSHPem('TEST', {}, Uint8List.fromList([1, 2, 3])).encode(-1),
      throwsA(isA<ArgumentError>()),
    );
  });
}

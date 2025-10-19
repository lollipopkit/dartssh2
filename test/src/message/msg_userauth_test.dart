import 'dart:typed_data';

import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  test('hostbased factory enforces ASCII host name', () {
    expect(
      () => SSH_Message_Userauth_Request.hostbased(
        username: 'user',
        publicKeyAlgorithm: 'ssh-ed25519',
        publicKey: Uint8List(0),
        hostName: 'hé.example.com',
        userNameOnClientHost: 'user',
        signature: Uint8List(0),
      ),
      throwsArgumentError,
    );

    expect(
      SSH_Message_Userauth_Request.hostbased(
        username: 'user',
        publicKeyAlgorithm: 'ssh-ed25519',
        publicKey: Uint8List(0),
        hostName: 'host.example.com',
        userNameOnClientHost: 'user',
        signature: Uint8List(0),
      ).hostName,
      'host.example.com',
    );
  });

  test('hostbased decode rejects non-ASCII host name', () {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSH_Message_Userauth_Request.messageId);
    writer.writeUtf8('user');
    writer.writeUtf8('ssh-connection');
    writer.writeUtf8('hostbased');
    writer.writeUtf8('ssh-ed25519');
    writer.writeString(Uint8List(0));
    writer.writeUtf8('hé.example.com');
    writer.writeUtf8('clientuser');
    writer.writeString(Uint8List(0));

    final bytes = writer.takeBytes();

    expect(
      () => SSH_Message_Userauth_Request.decode(bytes),
      throwsFormatException,
    );
  });
}

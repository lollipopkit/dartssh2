import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  test('x11 request encodes screen number as uint32', () {
    final message = SSH_Message_Channel_Request.x11(
      recipientChannel: 7,
      wantReply: true,
      singleConnection: true,
      x11AuthenticationProtocol: 'MIT-MAGIC-COOKIE-1',
      x11AuthenticationCookie: '0123456789abcdef',
      x11ScreenNumber: 3,
    );

    final encoded = message.encode();
    final decoded = SSH_Message_Channel_Request.decode(encoded);

    expect(decoded.x11ScreenNumber, 3);
    expect(decoded.singleConnection, true);
    expect(decoded.x11AuthenticationProtocol, 'MIT-MAGIC-COOKIE-1');
    expect(decoded.x11AuthenticationCookie, '0123456789abcdef');
  });

  test('x11 request factory rejects non-hex cookies', () {
    expect(
      () => SSH_Message_Channel_Request.x11(
        recipientChannel: 1,
        x11AuthenticationProtocol: 'MIT-MAGIC-COOKIE-1',
        x11AuthenticationCookie: 'not-hex',
        x11ScreenNumber: 0,
      ),
      throwsArgumentError,
    );
  });

  test('x11 request decode rejects invalid cookie', () {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSH_Message_Channel_Request.messageId);
    writer.writeUint32(2);
    writer.writeUtf8(SSHChannelRequestType.x11);
    writer.writeBool(true);
    writer.writeBool(false);
    writer.writeUtf8('MIT-MAGIC-COOKIE-1');
    writer.writeUtf8('badcookie');
    writer.writeUint32(0);
    final encoded = writer.takeBytes();
    expect(
      () => SSH_Message_Channel_Request.decode(encoded),
      throwsFormatException,
    );
  });

  test('xon-xoff request encodes client flow control flag', () {
    final message = SSH_Message_Channel_Request.xonXoff(
      recipientChannel: 4,
      clientCanDo: true,
    );

    final encoded = message.encode();
    final decoded = SSH_Message_Channel_Request.decode(encoded);

    expect(decoded.requestType, SSHChannelRequestType.xon);
    expect(decoded.clientCanDo, true);
    expect(decoded.wantReply, false);
  });

  test('exit-signal request defaults to empty strings', () {
    final message = SSH_Message_Channel_Request.exitSignal(
      recipientChannel: 5,
      exitSignalName: 'TERM',
    );

    final encoded = message.encode();
    final decoded = SSH_Message_Channel_Request.decode(encoded);

    expect(decoded.exitSignalName, 'TERM');
    expect(decoded.coreDumped, false);
    expect(decoded.errorMessage, '');
    expect(decoded.languageTag, '');
  });

  test('exit-signal request encodes provided strings', () {
    final message = SSH_Message_Channel_Request.exitSignal(
      recipientChannel: 6,
      exitSignalName: 'KILL',
      coreDumped: true,
      errorMessage: 'terminated',
      languageTag: 'en-US',
    );

    final encoded = message.encode();
    final decoded = SSH_Message_Channel_Request.decode(encoded);

    expect(decoded.exitSignalName, 'KILL');
    expect(decoded.coreDumped, true);
    expect(decoded.errorMessage, 'terminated');
    expect(decoded.languageTag, 'en-US');
  });
}

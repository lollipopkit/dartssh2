import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  test('tcpip-forward defaults to wantReply true', () {
    final request = SSH_Message_Global_Request.tcpipForward('127.0.0.1', 8080);
    final encoded = request.encode();
    final decoded = SSH_Message_Global_Request.decode(encoded);

    expect(decoded.requestName, 'tcpip-forward');
    expect(decoded.wantReply, isTrue);
    expect(decoded.bindAddress, '127.0.0.1');
    expect(decoded.bindPort, 8080);
  });

  test('tcpip-forward can disable wantReply', () {
    final request = SSH_Message_Global_Request.tcpipForward(
      '::1',
      2222,
      wantReply: false,
    );
    final encoded = request.encode();
    final decoded = SSH_Message_Global_Request.decode(encoded);

    expect(decoded.requestName, 'tcpip-forward');
    expect(decoded.wantReply, isFalse);
    expect(decoded.bindAddress, '::1');
    expect(decoded.bindPort, 2222);
  });

  test('cancel-tcpip-forward honors wantReply flag', () {
    final request = SSH_Message_Global_Request.cancelTcpipForward(
      bindAddress: '0.0.0.0',
      bindPort: 9000,
      wantReply: false,
    );
    final encoded = request.encode();
    final decoded = SSH_Message_Global_Request.decode(encoded);

    expect(decoded.requestName, 'cancel-tcpip-forward');
    expect(decoded.wantReply, isFalse);
    expect(decoded.bindAddress, '0.0.0.0');
    expect(decoded.bindPort, 9000);
  });
}

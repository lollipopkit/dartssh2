import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_client.dart';
import 'package:test/test.dart';

void main() {
  test('missing forwarded tcpip uses administratively prohibited code', () {
    final failure = SSHClient.buildForwardedTcpipFailure(
      recipientChannel: 7,
      description: 'missing',
    );

    expect(failure.reasonCode,
        SSH_Message_Channel_Open_Failure.codeAdministrativelyProhibited);
  });
}

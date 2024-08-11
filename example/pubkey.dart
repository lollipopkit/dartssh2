import 'dart:convert';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

void main(List<String> args) async {
  final socket = await SSHSocket.connect('localhost', 22);

  final keyPwd = '';
  final keyFile = await File('${Platform.environment['HOME']}/.ssh/id_ecdsa')
      .readAsString();
  // A single private key file may contain multiple keys.
  final keys = SSHKeyPair.fromPem(keyFile, keyPwd);
  final user = Platform.environment['USER'];

  final client = SSHClient(
    socket,
    username: user!,
    identities: keys,
    printDebug: print,
    printTrace: print,
  );

  //await client.run('sleep 12');
  final uptime = await client.run('uptime');
  print(utf8.decode(uptime));

  client.close();
  await client.done;
}

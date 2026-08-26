// Connects to a real network host; excluded from the web job below via the
// integration tag, but @TestOn('vm') is added defensively too.
@TestOn('vm')
@Tags(['integration'])
library;

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSHSocket', () {
    test('can establish tcp connections', () async {
      final socket = await SSHSocket.connect('test.rebex.net', 22);
      final firstPacket = await socket.stream.first;
      expect(firstPacket, isNotEmpty);
      await socket.close();
    });
  });
}

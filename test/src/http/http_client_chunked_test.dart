import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/src/http/http_client.dart';
import 'package:dartssh2/src/http/http_headers.dart';
import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:test/test.dart';

class _NullSink implements StreamSink<List<int>> {
  @override
  void add(List<int> event) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future addStream(Stream<List<int>> stream) async {}

  @override
  Future close() async {}

  @override
  Future get done => Future.value();
}

class _FakeSocket implements SSHSocket {
  _FakeSocket(List<int> bytes)
      : _controller = StreamController<Uint8List>() {
    // Emit bytes then close.
    _controller.add(Uint8List.fromList(bytes));
    _controller.close();
  }

  final StreamController<Uint8List> _controller;

  @override
  Future<void> close() async {
    await _controller.close();
  }

  @override
  void destroy() {
    _controller.close();
  }

  @override
  Future<void> get done => _controller.done;

  @override
  StreamSink<List<int>> get sink => _NullSink();

  @override
  Stream<Uint8List> get stream => _controller.stream;
}

void main() {
  group('SSHHttpClientResponse chunked decoding', () {
    test('decodes simple chunked body', () async {
      const response =
          'HTTP/1.1 200 OK\r\n'
          'Content-Type: text/plain; charset=utf-8\r\n'
          'Transfer-Encoding: chunked\r\n'
          '\r\n'
          '7\r\n'
          'Mozilla\r\n'
          '9\r\n'
          'Developer\r\n'
          '7\r\n'
          'Network\r\n'
          '0\r\n'
          '\r\n';

      final socket = _FakeSocket(response.codeUnits);
      final res = await SSHHttpClientResponse.from(socket);

      expect(res.statusCode, 200);
      expect(res.headers.value(SSHHttpHeaders.transferEncodingHeader), 'chunked');
      expect(res.headers.contentLength, -1);
      expect(res.body, 'MozillaDeveloperNetwork');
    });
  });
}


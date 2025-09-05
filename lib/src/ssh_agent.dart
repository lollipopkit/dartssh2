import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_errors.dart';

/// SSH Agent protocol implementation
class SSHAgent {
  static const _agentRequestIdentities = 11;
  static const _agentIdentitiesAnswer = 12;
  static const _agentSignRequest = 13;
  static const _agentSignResponse = 14;
  static const _agentFailure = 5;

  final String? socketPath;
  final SSHChannel? channel;
  Socket? _socket;
  final StreamController<Uint8List> _responseController = StreamController<Uint8List>();

  SSHAgent({this.socketPath, this.channel}) {
    if (socketPath != null) {
      _connectToSocket();
    } else if (channel != null) {
      _setupChannelCommunication();
    }
  }

  void _connectToSocket() {
    if (socketPath == null) return;
    
    Socket.connect(socketPath!.split(':').first, int.parse(socketPath!.split(':').last))
      .then((socket) {
        _socket = socket;
        _socket!.listen(
          (data) => _responseController.add(data),
          onError: (error) => _responseController.addError(error),
          onDone: () => _responseController.close(),
        );
      })
      .catchError((error) {
        _responseController.addError(error);
      });
  }

  void _setupChannelCommunication() {
    if (channel == null) return;

    channel!.stream.listen((data) {
      _responseController.add(data.bytes);
    }, onError: (error) {
      _responseController.addError(error);
    }, onDone: () {
      _responseController.close();
    });
  }

  Future<Uint8List> _sendRequest(Uint8List request) async {
    if (_socket != null) {
      _socket!.add(request);
      return await _responseController.stream.first;
    } else if (channel != null) {
      channel!.addData(request);
      return await _responseController.stream.first;
    } else {
      throw SSHStateError('No communication channel available');
    }
  }

  Future<List<SSHIdentity>> requestIdentities() async {
    final writer = SSHMessageWriter();
    writer.writeUint32(1); // Message length
    writer.writeUint8(_agentRequestIdentities);
    
    final response = await _sendRequest(writer.takeBytes());
    final reader = SSHMessageReader(response);
    
    final type = reader.readUint8();
    if (type == _agentFailure) {
      throw SSHStateError('Agent failed to list identities');
    }
    
    if (type != _agentIdentitiesAnswer) {
      throw SSHStateError('Unexpected response type: $type');
    }
    
    final numIdentities = reader.readUint32();
    final identities = <SSHIdentity>[];
    
    for (int i = 0; i < numIdentities; i++) {
      final blob = reader.readString();
      final comment = reader.readUtf8();
      identities.add(SSHIdentity(blob: blob, comment: comment));
    }
    
    return identities;
  }

  Future<Uint8List> sign(Uint8List data, Uint8List keyBlob) async {
    final writer = SSHMessageWriter();
    final dataLength = 1 + 4 + keyBlob.length + 4 + data.length;
    writer.writeUint32(dataLength);
    writer.writeUint8(_agentSignRequest);
    writer.writeString(keyBlob);
    writer.writeString(data);
    writer.writeUint32(0); // Flags
    
    final response = await _sendRequest(writer.takeBytes());
    final reader = SSHMessageReader(response);
    
    final type = reader.readUint8();
    if (type == _agentFailure) {
      throw SSHStateError('Agent failed to sign data');
    }
    
    if (type != _agentSignResponse) {
      throw SSHStateError('Unexpected response type: $type');
    }
    
    return reader.readString();
  }

  void dispose() {
    _responseController.close();
    _socket?.close();
  }
}

class SSHIdentity {
  final Uint8List blob;
  final String comment;

  SSHIdentity({required this.blob, required this.comment});
}
// ignore_for_file: camel_case_types

import 'dart:typed_data';
import 'package:dartssh2/src/ssh_message.dart';

class SSH_Message_Unimplemented implements SSHMessage {
  static const int messageId = 3;

  final int sequenceNumber;

  SSH_Message_Unimplemented(this.sequenceNumber);

  factory SSH_Message_Unimplemented.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    reader.skip(1); // Skip the message ID
    final sequenceNumber = reader.readUint32();
    return SSH_Message_Unimplemented(sequenceNumber);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(sequenceNumber);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Unimplemented(sequenceNumber: $sequenceNumber)';
  }
}
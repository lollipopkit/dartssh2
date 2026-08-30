import 'dart:typed_data';

import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

void main() {
  group('SftpFileMode', () {
    test('factory sets expected permission flags', () {
      final mode = SftpFileMode(
        userRead: true,
        userWrite: false,
        userExecute: true,
        groupRead: false,
        groupWrite: true,
        groupExecute: false,
        otherRead: true,
        otherWrite: false,
        otherExecute: true,
      );

      expect(mode.userRead, isTrue);
      expect(mode.userWrite, isFalse);
      expect(mode.userExecute, isTrue);
      expect(mode.groupRead, isFalse);
      expect(mode.groupWrite, isTrue);
      expect(mode.groupExecute, isFalse);
      expect(mode.otherRead, isTrue);
      expect(mode.otherWrite, isFalse);
      expect(mode.otherExecute, isTrue);
    });

    test('type detection covers all known mode masks', () {
      expect(const SftpFileMode.value(1 << 12).type, SftpFileType.pipe);
      expect(
        const SftpFileMode.value(1 << 13).type,
        SftpFileType.characterDevice,
      );
      expect(const SftpFileMode.value(1 << 14).type, SftpFileType.directory);
      expect(
        const SftpFileMode.value((1 << 14) + (1 << 13)).type,
        SftpFileType.blockDevice,
      );
      expect(const SftpFileMode.value(1 << 15).type, SftpFileType.regularFile);
      expect(
        const SftpFileMode.value((1 << 15) + (1 << 13)).type,
        SftpFileType.symbolicLink,
      );
      expect(
        const SftpFileMode.value((1 << 15) + (1 << 14)).type,
        SftpFileType.socket,
      );
      expect(
        const SftpFileMode.value((1 << 15) + (1 << 14) + (1 << 13)).type,
        SftpFileType.whiteout,
      );
      expect(const SftpFileMode.value(0).type, SftpFileType.unknown);
    });
  });

  group('SftpFileAttrs', () {
    test('writeTo/readFrom roundtrip keeps all fields', () {
      final attrs = SftpFileAttrs(
        size: 987654321,
        userID: 1001,
        groupID: 1002,
        mode: const SftpFileMode.value((1 << 14) + 0x1A4),
        accessTime: 1700000000,
        modifyTime: 1700000100,
        extended: const {'keyA': 'valueA', 'keyB': 'valueB'},
      );

      final writer = SSHMessageWriter();
      attrs.writeTo(writer);

      final reader = SSHMessageReader(writer.takeBytes());
      final decoded = SftpFileAttrs.readFrom(reader);

      expect(decoded.size, attrs.size);
      expect(decoded.userID, attrs.userID);
      expect(decoded.groupID, attrs.groupID);
      expect(decoded.mode?.value, attrs.mode?.value);
      expect(decoded.accessTime, attrs.accessTime);
      expect(decoded.modifyTime, attrs.modifyTime);
      expect(decoded.extended, attrs.extended);
    });

    test('type helper getters reflect mode type', () {
      final attrs = SftpFileAttrs(
        mode: const SftpFileMode.value((1 << 15) + (1 << 13)),
      );

      expect(attrs.isSymbolicLink, isTrue);
      expect(attrs.isDirectory, isFalse);
      expect(attrs.isFile, isFalse);
      expect(attrs.type, SftpFileType.symbolicLink);
    });

    test('lone userID does not raise the uidgid flag or write a short field',
        () {
      final writer = SSHMessageWriter();
      SftpFileAttrs(userID: 1000).writeTo(writer);

      // flags(4) only - no uid/gid bytes at all.
      expect(writer.takeBytes(), Uint8List.fromList([0, 0, 0, 0]));
    });

    test('lone groupID does not raise the uidgid flag or write a short field',
        () {
      final writer = SSHMessageWriter();
      SftpFileAttrs(groupID: 1000).writeTo(writer);

      expect(writer.takeBytes(), Uint8List.fromList([0, 0, 0, 0]));
    });

    test(
        'lone accessTime does not raise the acmodtime flag or write a short '
        'field', () {
      final writer = SSHMessageWriter();
      SftpFileAttrs(accessTime: 5).writeTo(writer);

      expect(writer.takeBytes(), Uint8List.fromList([0, 0, 0, 0]));
    });

    test(
        'lone modifyTime does not raise the acmodtime flag or write a short '
        'field', () {
      final writer = SSHMessageWriter();
      SftpFileAttrs(modifyTime: 5).writeTo(writer);

      expect(writer.takeBytes(), Uint8List.fromList([0, 0, 0, 0]));
    });

    test('full uidgid and acmodtime pairs still round-trip', () {
      final attrs = SftpFileAttrs(
        userID: 1000,
        groupID: 2000,
        accessTime: 111,
        modifyTime: 222,
      );

      final writer = SSHMessageWriter();
      attrs.writeTo(writer);

      final bytes = writer.takeBytes();
      // flags(4) + uid(4) + gid(4) + atime(4) + mtime(4) = 20 bytes, no
      // short/misaligned fields.
      expect(bytes.length, 20);

      final reader = SSHMessageReader(bytes);
      final decoded = SftpFileAttrs.readFrom(reader);
      expect(decoded.userID, 1000);
      expect(decoded.groupID, 2000);
      expect(decoded.accessTime, 111);
      expect(decoded.modifyTime, 222);
    });

    test('mixed partial and full fields: only the complete pair is written',
        () {
      // userID is lone (dropped), size + full acmodtime pair are present.
      final attrs = SftpFileAttrs(
        size: 42,
        userID: 1000,
        accessTime: 10,
        modifyTime: 20,
      );

      final writer = SSHMessageWriter();
      attrs.writeTo(writer);

      final reader = SSHMessageReader(writer.takeBytes());
      final decoded = SftpFileAttrs.readFrom(reader);
      expect(decoded.size, 42);
      expect(decoded.userID, isNull);
      expect(decoded.groupID, isNull);
      expect(decoded.accessTime, 10);
      expect(decoded.modifyTime, 20);
    });
  });
}

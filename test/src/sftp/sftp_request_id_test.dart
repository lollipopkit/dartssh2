import 'package:dartssh2/src/sftp/sftp_request_id.dart';
import 'package:test/test.dart';

void main() {
  group('SftpRequestId', () {
    test('produces a sequential series starting at 0', () {
      final id = SftpRequestId();
      expect(id.next, 0);
      expect(id.next, 1);
      expect(id.next, 2);
    });

    test('wraps around at max without losing precision', () {
      // Seed the counter right at the wrap boundary instead of calling
      // `next` 4+ billion times.
      final id = SftpRequestId(initial: SftpRequestId.max - 1);

      expect(id.next, SftpRequestId.max - 1);
      // Wraps back to 0 rather than emitting `max` itself, matching the
      // original `_id++ % max` behavior (max % max == 0).
      expect(id.next, 0);
      expect(id.next, 1);
    });

    test('internal counter never exceeds max, so no precision loss', () {
      final id = SftpRequestId(initial: SftpRequestId.max - 1);

      // Drive many wraps; every returned value must stay within the
      // 32-bit range and follow the expected 0..max-1 cycle.
      for (var i = 0; i < 5; i++) {
        final value = id.next;
        expect(value, greaterThanOrEqualTo(0));
        expect(value, lessThan(SftpRequestId.max));
      }
    });

    test('seeding with an out-of-range initial value wraps immediately', () {
      final id = SftpRequestId(initial: SftpRequestId.max);
      expect(id.next, 0);
      expect(id.next, 1);
    });
  });
}

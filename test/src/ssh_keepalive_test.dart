import 'dart:async';

import 'package:dartssh2/src/ssh_keepalive.dart';
import 'package:test/test.dart';

void main() {
  group('SSHKeepAlive', () {
    test('calls ping at specified interval', () async {
      var pingCount = 0;
      final completer = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        ping: () async {
          pingCount++;
          if (pingCount >= 3) {
            completer.complete();
          }
        },
      );

      keepAlive.start();
      await completer.future;
      keepAlive.stop();

      expect(pingCount, greaterThanOrEqualTo(3));
    });

    test('prevents overlapping pings', () async {
      var pingCount = 0;
      var activePings = 0;
      var maxActivePings = 0;
      final completer = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        ping: () async {
          pingCount++;
          activePings++;
          if (activePings > maxActivePings) {
            maxActivePings = activePings;
          }
          // Sleep longer than the interval to cause an overlapping tick
          await Future.delayed(const Duration(milliseconds: 50));
          activePings--;
          if (pingCount >= 2 && !completer.isCompleted) {
            completer.complete();
          }
        },
      );

      keepAlive.start();
      // Wait for a few intervals. If overlapping wasn't prevented, activePings would exceed 1.
      await Future.delayed(const Duration(milliseconds: 100));
      keepAlive.stop();

      expect(maxActivePings, equals(1));
    });

    test('handles ping errors and resets isPinging status', () async {
      var pingCount = 0;
      final completer = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        ping: () async {
          pingCount++;
          if (pingCount == 1) {
            throw Exception('ping failed');
          }
          if (pingCount == 2) {
            completer.complete();
          }
        },
      );

      keepAlive.start();
      await completer.future;
      keepAlive.stop();

      expect(pingCount, equals(2));
    });

    test('calls onDead after maxMissed unanswered ticks', () async {
      var pingCount = 0;
      final dead = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        maxMissed: 3,
        // Never answered.
        ping: () {
          pingCount++;
          return Completer<void>().future;
        },
        onDead: dead.complete,
      );

      keepAlive.start();
      await dead.future.timeout(const Duration(seconds: 1));
      // Stopped: no later tick sends another ping or calls onDead again.
      await Future.delayed(const Duration(milliseconds: 50));

      expect(pingCount, equals(1));
    });

    test('a reply resets the missed count', () async {
      var pingCount = 0;
      var dead = false;
      final done = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        maxMissed: 3,
        // Each reply misses a tick: slow, but never three in a row.
        ping: () async {
          pingCount++;
          await Future.delayed(const Duration(milliseconds: 15));
          if (pingCount >= 4 && !done.isCompleted) done.complete();
        },
        onDead: () => dead = true,
      );

      keepAlive.start();
      await done.future;
      keepAlive.stop();

      expect(dead, isFalse);
    });

    test('a failed ping is not counted as missed', () async {
      var pingCount = 0;
      var dead = false;
      final done = Completer<void>();

      final keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 10),
        maxMissed: 1,
        ping: () async {
          pingCount++;
          if (pingCount >= 5 && !done.isCompleted) done.complete();
          throw Exception('closing');
        },
        onDead: () => dead = true,
      );

      keepAlive.start();
      await done.future;
      keepAlive.stop();

      expect(dead, isFalse);
    });
  });
}

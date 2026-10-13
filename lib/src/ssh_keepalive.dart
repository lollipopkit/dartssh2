import 'dart:async';

/// A wrapper around [Timer] that calls [ping] every [interval], and can be
/// started or stopped idempotently.
///
/// A ping still unanswered at a tick counts as a missed one; after
/// [maxMissed] in a row [onDead] is called and the keep-alive stops, as
/// OpenSSH's `ServerAliveCountMax` does. Counted in ticks rather than timed:
/// a process suspended mid-ping wakes to a tick with its reply possibly still
/// in flight, and it takes [maxMissed] ticks of running time to decide.
class SSHKeepAlive {
  Timer? _timer;

  final Duration interval;

  final Future Function() ping;

  /// Unanswered ticks before the connection is given up on.
  final int maxMissed;

  /// Called once [maxMissed] ticks pass without a reply.
  final void Function()? onDead;

  bool _isPinging = false;

  int _missed = 0;

  SSHKeepAlive({
    required this.ping,
    this.interval = const Duration(seconds: 10),
    this.maxMissed = 3,
    this.onDead,
  }) : assert(maxMissed > 0);

  void start() {
    _timer ??= Timer.periodic(interval, (timer) async {
      if (_isPinging) {
        if (++_missed >= maxMissed) {
          stop();
          onDead?.call();
        }
        return;
      }
      _isPinging = true;
      try {
        await ping();
        _missed = 0;
      } catch (_) {
        // A ping that fails rather than hangs means the transport is already
        // closing, and it reports that itself.
      } finally {
        _isPinging = false;
      }
    });
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
    _missed = 0;
  }
}

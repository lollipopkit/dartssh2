import 'dart:async';
import 'dart:collection';

/// Advanced DoS protection for SSH connections
/// Implements rate limiting, connection monitoring, and resource controls
class SSHDoSProtection {
  /// Maximum number of concurrent connections per remote host
  static const int maxConnectionsPerHost = 5;
  
  /// Maximum number of total concurrent connections
  static const int maxTotalConnections = 50;
  
  /// Connection rate limit (connections per minute)
  static const int connectionsPerMinute = 10;
  
  /// Packet rate limit (packets per second)
  static const int packetsPerSecond = 1000;
  
  /// Memory usage limit per connection (in bytes)
  static const int maxMemoryPerConnection = 50 * 1024 * 1024; // 50MB
  
  /// Maximum authentication attempts per minute
  static const int authAttemptsPerMinute = 5;
  
  /// Connection tracking by host
  final _hostConnections = <String?, int>{};
  
  /// Rate limiting by host
  final _connectionRates = <String?, Queue<DateTime>>{};
  
  /// Authentication attempt tracking by host
  final _authRates = <String?, Queue<DateTime>>{};
  
  /// Packet rate tracking by connection
  final _packetRates = <String?, Queue<DateTime>>{};
  
  /// Memory usage tracking by connection
  final _memoryUsage = <String?, int>{};
  
  /// Total active connections
  int _totalConnections = 0;
  
  /// Timer for cleaning up old entries
  Timer? _cleanupTimer;
  
  SSHDoSProtection() {
    _startCleanupTimer();
  }
  
  /// Check if a new connection is allowed from the given host
  bool allowConnection(String? host, {String? connectionId}) {
    // Check total connection limit
    if (_totalConnections >= maxTotalConnections) {
      throw SSHDoSProtectionError(
        'Maximum total connections ($maxTotalConnections) exceeded',
        SSHDoSProtectionType.totalConnectionsLimit,
      );
    }
    
    // Check per-host connection limit
    final hostCount = _hostConnections[host] ?? 0;
    if (hostCount >= maxConnectionsPerHost) {
      throw SSHDoSProtectionError(
        'Maximum connections per host ($maxConnectionsPerHost) exceeded for $host',
        SSHDoSProtectionType.hostConnectionsLimit,
      );
    }
    
    // Check connection rate limit
    if (!_checkRateLimit(host, _connectionRates, connectionsPerMinute, const Duration(minutes: 1))) {
      throw SSHDoSProtectionError(
        'Connection rate limit ($connectionsPerMinute per minute) exceeded for $host',
        SSHDoSProtectionType.connectionRateLimit,
      );
    }
    
    // Record the connection
    if (connectionId != null) {
      _recordConnection(host, connectionId);
    }
    
    return true;
  }
  
  /// Check if an authentication attempt is allowed
  bool allowAuthentication(String? host) {
    if (!_checkRateLimit(host, _authRates, authAttemptsPerMinute, const Duration(minutes: 1))) {
      throw SSHDoSProtectionError(
        'Authentication rate limit ($authAttemptsPerMinute per minute) exceeded for $host',
        SSHDoSProtectionType.authRateLimit,
      );
    }
    
    // Record the authentication attempt
    _authRates.putIfAbsent(host, () => Queue());
    _authRates[host]!.add(DateTime.now());
    
    return true;
  }
  
  /// Check if packet sending is allowed
  bool allowPacket(String connectionId) {
    if (!_checkRateLimit(connectionId, _packetRates, packetsPerSecond, const Duration(seconds: 1))) {
      throw SSHDoSProtectionError(
        'Packet rate limit ($packetsPerSecond per second) exceeded',
        SSHDoSProtectionType.packetRateLimit,
      );
    }
    
    // Record the packet
    _packetRates.putIfAbsent(connectionId, () => Queue());
    _packetRates[connectionId]!.add(DateTime.now());
    
    return true;
  }
  
  /// Update memory usage for a connection
  void updateMemoryUsage(String connectionId, int bytes) {
    _memoryUsage[connectionId] = bytes;
    
    if (bytes > maxMemoryPerConnection) {
      throw SSHDoSProtectionError(
        'Memory usage limit ($maxMemoryPerConnection bytes) exceeded',
        SSHDoSProtectionType.memoryLimit,
      );
    }
  }
  
  /// Record a new connection
  void _recordConnection(String? host, String connectionId) {
    _hostConnections[host] = (_hostConnections[host] ?? 0) + 1;
    _totalConnections++;
    
    // Record connection timestamp for rate limiting
    _connectionRates.putIfAbsent(host, () => Queue());
    _connectionRates[host]!.add(DateTime.now());
    
    // Initialize packet rate tracking
    _packetRates[connectionId] = Queue();
    _memoryUsage[connectionId] = 0;
  }
  
  /// Remove a connection
  void removeConnection(String? host, String connectionId) {
    _hostConnections[host] = (_hostConnections[host] ?? 1) - 1;
    if (_hostConnections[host] == 0) {
      _hostConnections.remove(host);
    }
    _totalConnections--;
    
    // Clean up tracking data
    _connectionRates[host]?.removeWhere((timestamp) => 
      DateTime.now().difference(timestamp) > const Duration(minutes: 1));
    if (_connectionRates[host]?.isEmpty == true) {
      _connectionRates.remove(host);
    }
    
    _packetRates.remove(connectionId);
    _memoryUsage.remove(connectionId);
  }
  
  /// Check rate limit for a given key
  bool _checkRateLimit(String? key, Map<String?, Queue<DateTime>> rates, int maxRequests, Duration window) {
    final now = DateTime.now();
    final queue = rates.putIfAbsent(key, () => Queue());
    
    // Remove old entries
    while (queue.isNotEmpty && now.difference(queue.first) > window) {
      queue.removeFirst();
    }
    
    return queue.length < maxRequests;
  }
  
  /// Start cleanup timer
  void _startCleanupTimer() {
    _cleanupTimer = Timer.periodic(const Duration(minutes: 5), (_) {
      _cleanup();
    });
  }
  
  /// Cleanup old entries
  void _cleanup() {
    final now = DateTime.now();
    
    // Clean up connection rates
    _connectionRates.forEach((host, queue) {
      queue.removeWhere((timestamp) => now.difference(timestamp) > const Duration(minutes: 1));
    });
    _connectionRates.removeWhere((host, queue) => queue.isEmpty);
    
    // Clean up auth rates
    _authRates.forEach((host, queue) {
      queue.removeWhere((timestamp) => now.difference(timestamp) > const Duration(minutes: 1));
    });
    _authRates.removeWhere((host, queue) => queue.isEmpty);
    
    // Clean up packet rates
    _packetRates.forEach((connectionId, queue) {
      queue.removeWhere((timestamp) => now.difference(timestamp) > const Duration(seconds: 1));
    });
    _packetRates.removeWhere((connectionId, queue) => queue.isEmpty);
  }
  
  /// Get current statistics
  Map<String, dynamic> getStatistics() {
    return {
      'totalConnections': _totalConnections,
      'hostConnections': Map.from(_hostConnections),
      'activeConnectionRates': _connectionRates.map((host, queue) => MapEntry(host, queue.length)),
      'activeAuthRates': _authRates.map((host, queue) => MapEntry(host, queue.length)),
      'activePacketRates': _packetRates.map((connectionId, queue) => MapEntry(connectionId, queue.length)),
      'memoryUsage': Map.from(_memoryUsage),
    };
  }
  
  /// Dispose resources
  void dispose() {
    _cleanupTimer?.cancel();
    _hostConnections.clear();
    _connectionRates.clear();
    _authRates.clear();
    _packetRates.clear();
    _memoryUsage.clear();
  }
}

/// DoS protection error types
enum SSHDoSProtectionType {
  totalConnectionsLimit,
  hostConnectionsLimit,
  connectionRateLimit,
  authRateLimit,
  packetRateLimit,
  memoryLimit,
}

/// DoS protection error
class SSHDoSProtectionError implements Exception {
  final String message;
  final SSHDoSProtectionType type;
  
  SSHDoSProtectionError(this.message, this.type);
  
  @override
  String toString() => 'SSHDoSProtectionError($type): $message';
}
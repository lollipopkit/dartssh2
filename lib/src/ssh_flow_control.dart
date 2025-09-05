import 'dart:math';

/// Manages adaptive flow control for SSH channels based on network conditions
/// and performance metrics. Implements RFC 4254 compliant window management
/// with optimizations for various network scenarios.
class SSHChannelFlowController {
  // Default configuration constants
  static const int _defaultInitialWindowSize = 2 * 1024 * 1024; // 2MB
  static const int _minWindowSize = 32 * 1024; // 32KB minimum
  static const int _maxWindowSize = 0xFFFFFFFF; // 2^32-1 RFC max
  static const double _defaultThresholdRatio = 0.5; // 50% of window
  
  // Performance monitoring constants
  static const int _performanceHistorySize = 10;
  static const Duration _throughputMeasurementWindow = Duration(seconds: 2);
  
  // Adaptive algorithm parameters
  static const double _congestionThreshold = 0.7; // 70% reduction indicates congestion
  static const double _windowDecreaseMultiplier = 0.75;
  static const int _adaptationSmoothingFactor = 4; // Number of measurements to smooth
  
  // Congestion control parameters (inspired by TCP)
  static const double _slowStartMultiplier = 2.0; // Exponential growth in slow start
  static const double _congestionAvoidanceIncrement = 0.1; // Linear growth in congestion avoidance

  final int initialWindowSize;
  final int minimumWindowSize;
  final int maximumWindowSize;
  final double thresholdRatio;
  final bool enableAdaptiveResizing;
  final void Function(String)? debugPrint;

  /// Current window size being advertised
  int _currentWindowSize;
  
  /// Current local window (available space)
  int _localWindow;
  
  /// Dynamic threshold for window adjustments
  int _currentThreshold;
  
  /// Performance monitoring data
  final List<_PerformanceMetric> _performanceHistory = [];
  DateTime? _lastDataReceivedTime;
  int _bytesReceivedSinceLastMeasurement = 0;
  int _totalBytesReceived = 0;
  
  /// Congestion control state
  bool _congestionDetected = false;
  int _consecutiveGoodMeasurements = 0;
  double _estimatedRtt = 100.0; // Default 100ms RTT
  double _estimatedBandwidth = 1024 * 1024; // Default 1MB/s
  
  /// TCP-like congestion control state
  int _slowStartThreshold = 0; // Will be initialized
  bool _inSlowStart = true;
  
  /// Window exhaustion tracking for improved congestion detection
  final List<DateTime> _windowExhaustionEvents = [];
  DateTime? _lastWindowAdjustTime;

  SSHChannelFlowController({
    this.initialWindowSize = _defaultInitialWindowSize,
    this.minimumWindowSize = _minWindowSize,
    this.maximumWindowSize = _maxWindowSize,
    this.thresholdRatio = _defaultThresholdRatio,
    this.enableAdaptiveResizing = true,
    this.debugPrint,
  }) : _currentWindowSize = initialWindowSize,
       _localWindow = initialWindowSize,
       _currentThreshold = (initialWindowSize * thresholdRatio).round() {
    
    // Initialize congestion control parameters
    _slowStartThreshold = initialWindowSize; // Start with initial window size as threshold
    
    // Validate configuration
    assert(minimumWindowSize > 0 && minimumWindowSize <= maximumWindowSize);
    assert(initialWindowSize >= minimumWindowSize && initialWindowSize <= maximumWindowSize);
    assert(thresholdRatio > 0.0 && thresholdRatio < 1.0);
  }

  /// Current local window size (available space for receiving data)
  int get localWindow => _localWindow;
  
  /// Current advertised window size
  int get currentWindowSize => _currentWindowSize;
  
  /// Current threshold for triggering window adjustments
  int get currentThreshold => _currentThreshold;
  
  /// Whether window adjustment is needed based on current state
  bool get needsWindowAdjustment => _localWindow <= _currentThreshold;
  
  /// Estimated round-trip time in milliseconds
  double get estimatedRtt => _estimatedRtt;
  
  /// Estimated bandwidth in bytes per second
  double get estimatedBandwidth => _estimatedBandwidth;

  /// Process incoming data and update flow control state
  void processIncomingData(int dataLength) {
    final now = DateTime.now();
    
    _localWindow -= dataLength;
    _bytesReceivedSinceLastMeasurement += dataLength;
    _totalBytesReceived += dataLength;
    _lastDataReceivedTime = now;
    
    // Track window exhaustion events for congestion detection
    if (_localWindow <= 0) {
      _windowExhaustionEvents.add(now);
      // Keep only recent events
      if (_windowExhaustionEvents.length > 10) {
        _windowExhaustionEvents.removeAt(0);
      }
    }
    
    // Update throughput measurements
    _updateThroughputMeasurement(now);
    
    debugPrint?.call(
      'FlowControl: processed ${dataLength}b, window: $_localWindow/$_currentWindowSize',
    );
  }

  /// Calculate the optimal number of bytes to add for window adjustment
  int calculateWindowAdjustment() {
    if (!needsWindowAdjustment) {
      return 0;
    }

    int targetWindowSize = _currentWindowSize;
    
    if (enableAdaptiveResizing) {
      targetWindowSize = _calculateAdaptiveWindowSize();
    }

    // Ensure target is within valid bounds
    targetWindowSize = targetWindowSize.clamp(minimumWindowSize, maximumWindowSize);
    
    final bytesToAdd = targetWindowSize - _localWindow;
    
    // Update state
    _currentWindowSize = targetWindowSize;
    _localWindow = targetWindowSize;
    _currentThreshold = (targetWindowSize * thresholdRatio).round();
    
    debugPrint?.call(
      'FlowControl: window adjustment +${bytesToAdd}b, new window: $targetWindowSize',
    );
    
    return bytesToAdd > 0 ? bytesToAdd : 0;
  }

  /// Calculate optimal window size based on network conditions using TCP-like algorithm
  int _calculateAdaptiveWindowSize() {
    // Check for congestion first
    if (_isNetworkCongestedByEvents()) {
      _handleCongestion();
    }
    
    // Start with current window size
    int newSize = _currentWindowSize;
    
    if (_congestionDetected) {
      // During congestion, reduce window size
      newSize = max(
        (newSize * _windowDecreaseMultiplier).round(),
        minimumWindowSize,
      );
      debugPrint?.call('FlowControl: congestion detected, reducing window to $newSize');
    } else {
      // No congestion detected, increase window based on current phase
      if (_inSlowStart) {
        // Slow start: exponential growth
        newSize = min(
          (newSize * _slowStartMultiplier).round(),
          _slowStartThreshold,
        );
        
        // Check if we should exit slow start
        if (newSize >= _slowStartThreshold) {
          _inSlowStart = false;
          debugPrint?.call('FlowControl: exiting slow start, entering congestion avoidance');
        }
        
        debugPrint?.call('FlowControl: slow start, increasing window to $newSize');
      } else {
        // Congestion avoidance: linear growth
        final increment = max(
          (newSize * _congestionAvoidanceIncrement).round(),
          1024, // Minimum increment of 1KB
        );
        newSize = min(newSize + increment, maximumWindowSize);
        
        debugPrint?.call('FlowControl: congestion avoidance, increasing window to $newSize');
      }
    }
    
    // Apply bandwidth-delay product constraints
    final bdp = (_estimatedBandwidth * _estimatedRtt / 1000).round();
    final optimalWindowSize = max(bdp * 2, minimumWindowSize); // 2x BDP for buffering
    
    // Don't exceed what the network can handle
    if (newSize > optimalWindowSize * 4) {
      newSize = optimalWindowSize * 4;
      debugPrint?.call('FlowControl: capping window size to 4x BDP: $newSize');
    }
    
    return newSize.clamp(minimumWindowSize, maximumWindowSize);
  }


  /// Update throughput measurements and detect congestion
  void _updateThroughputMeasurement(DateTime now) {
    if (_lastDataReceivedTime == null) {
      return;
    }

    final timeSinceLastUpdate = now.difference(_lastDataReceivedTime!);
    if (timeSinceLastUpdate < _throughputMeasurementWindow) {
      return;
    }

    if (_bytesReceivedSinceLastMeasurement > 0) {
      final throughput = _bytesReceivedSinceLastMeasurement / 
                        timeSinceLastUpdate.inMilliseconds * 1000;
      
      _addPerformanceMetric(throughput, now);
      _updateNetworkEstimates();
      _detectCongestion();
      
      _bytesReceivedSinceLastMeasurement = 0;
    }
  }

  /// Add a new performance metric and maintain history size
  void _addPerformanceMetric(double throughput, DateTime timestamp) {
    _performanceHistory.insert(0, _PerformanceMetric(throughput, timestamp));
    
    if (_performanceHistory.length > _performanceHistorySize) {
      _performanceHistory.removeRange(_performanceHistorySize, _performanceHistory.length);
    }
  }

  /// Update network bandwidth and RTT estimates
  void _updateNetworkEstimates() {
    if (_performanceHistory.isEmpty) return;
    
    // Smooth bandwidth estimate using exponential moving average
    final latestThroughput = _performanceHistory.first.throughput;
    const alpha = 0.2; // Smoothing factor
    _estimatedBandwidth = _estimatedBandwidth * (1 - alpha) + latestThroughput * alpha;
    
    // Update RTT estimate if we have window adjustment timing data
    if (_lastWindowAdjustTime != null && _performanceHistory.length >= 2) {
      final responseTime = _performanceHistory.first.timestamp
          .difference(_lastWindowAdjustTime!)
          .inMilliseconds
          .toDouble();
      
      if (responseTime > 0 && responseTime < 10000) { // Reasonable RTT bounds
        _estimatedRtt = _estimatedRtt * (1 - alpha) + responseTime * alpha;
      }
    }
    
    debugPrint?.call(
      'FlowControl: estimated BW=${_estimatedBandwidth.toInt()}B/s, RTT=${_estimatedRtt.toInt()}ms',
    );
  }

  /// Detect network congestion based on throughput patterns
  void _detectCongestion() {
    if (_performanceHistory.length < _adaptationSmoothingFactor) {
      return;
    }

    final recent = _performanceHistory.take(_adaptationSmoothingFactor).toList();
    final older = _performanceHistory
        .skip(_adaptationSmoothingFactor)
        .take(_adaptationSmoothingFactor)
        .toList();
    
    if (older.isEmpty) return;

    final recentAvg = recent.map((m) => m.throughput).reduce((a, b) => a + b) / recent.length;
    final olderAvg = older.map((m) => m.throughput).reduce((a, b) => a + b) / older.length;
    
    final throughputRatio = recentAvg / olderAvg;
    
    if (throughputRatio < _congestionThreshold) {
      _congestionDetected = true;
      _consecutiveGoodMeasurements = 0;
      debugPrint?.call('FlowControl: congestion detected (ratio: ${throughputRatio.toStringAsFixed(2)})');
    } else {
      _consecutiveGoodMeasurements++;
      if (_consecutiveGoodMeasurements >= _adaptationSmoothingFactor) {
        _congestionDetected = false;
        debugPrint?.call('FlowControl: congestion cleared');
      }
    }
  }

  /// Detect network congestion based on window exhaustion events (TCP-like)
  bool _isNetworkCongestedByEvents() {
    if (_windowExhaustionEvents.length < 3) return false;
    
    // Check if window exhaustions are happening more frequently
    final last3 = _windowExhaustionEvents.sublist(
      _windowExhaustionEvents.length - 3
    );
    final timeDiff1 = last3[1].difference(last3[0]).inMilliseconds;
    final timeDiff2 = last3[2].difference(last3[1]).inMilliseconds;
    
    // If time intervals are decreasing, congestion is likely increasing
    return timeDiff2 < timeDiff1 * 0.7 && timeDiff2 < 1000; // Less than 1 second between exhaustions
  }

  /// Handle detected congestion (TCP-like response)
  void _handleCongestion() {
    if (_congestionDetected) return; // Already handling congestion
    
    debugPrint?.call('FlowControl: Congestion detected, entering recovery mode');
    
    _congestionDetected = true;
    _consecutiveGoodMeasurements = 0;
    
    // Set slow start threshold to half of current window (TCP behavior)
    _slowStartThreshold = max(_currentWindowSize ~/ 2, minimumWindowSize);
    
    // Enter congestion avoidance mode
    _inSlowStart = false;
    
    debugPrint?.call('FlowControl: Set ssthresh to $_slowStartThreshold');
  }

  /// Reset flow control state (useful for new connections)
  void reset() {
    _currentWindowSize = initialWindowSize;
    _localWindow = initialWindowSize;
    _currentThreshold = (initialWindowSize * thresholdRatio).round();
    _performanceHistory.clear();
    _lastDataReceivedTime = null;
    _bytesReceivedSinceLastMeasurement = 0;
    _totalBytesReceived = 0;
    _congestionDetected = false;
    _consecutiveGoodMeasurements = 0;
    _estimatedRtt = 100.0;
    _estimatedBandwidth = 1024 * 1024;
    
    // Reset TCP-like congestion control state
    _slowStartThreshold = initialWindowSize;
    _inSlowStart = true;
    _windowExhaustionEvents.clear();
    
    debugPrint?.call('FlowControl: reset to initial state');
  }

  /// Get current performance statistics
  Map<String, dynamic> getStatistics() {
    final avgThroughput = _performanceHistory.isEmpty
        ? 0.0
        : _performanceHistory.map((m) => m.throughput).reduce((a, b) => a + b) / 
          _performanceHistory.length;
    
    return {
      'currentWindowSize': _currentWindowSize,
      'localWindow': _localWindow,
      'threshold': _currentThreshold,
      'totalBytesReceived': _totalBytesReceived,
      'estimatedBandwidth': _estimatedBandwidth,
      'estimatedRtt': _estimatedRtt,
      'averageThroughput': avgThroughput,
      'congestionDetected': _congestionDetected,
      'performanceHistorySize': _performanceHistory.length,
      'slowStartThreshold': _slowStartThreshold,
      'inSlowStart': _inSlowStart,
      'windowExhaustionEvents': _windowExhaustionEvents.length,
    };
  }
}

/// Internal class to track performance metrics
class _PerformanceMetric {
  final double throughput; // bytes per second
  final DateTime timestamp;
  
  _PerformanceMetric(this.throughput, this.timestamp);
}
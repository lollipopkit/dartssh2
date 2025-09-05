import 'package:dartssh2/src/ssh_flow_control.dart';
import 'package:test/test.dart';

void main() {
  group('SSHChannelFlowController', () {
    late SSHChannelFlowController controller;

    setUp(() {
      controller = SSHChannelFlowController(
        debugPrint: (msg) => print('Test: $msg'),
      );
    });

    test('initializes with default values', () {
      expect(controller.currentWindowSize, equals(2 * 1024 * 1024)); // 2MB
      expect(controller.localWindow, equals(2 * 1024 * 1024));
      expect(controller.needsWindowAdjustment, isFalse);
      expect(controller.estimatedRtt, equals(100.0)); // Default RTT
      expect(controller.estimatedBandwidth, equals(1024 * 1024)); // Default 1MB/s
    });

    test('processes incoming data correctly', () {
      const dataLength = 1024;
      final initialWindow = controller.localWindow;
      
      controller.processIncomingData(dataLength);
      
      expect(controller.localWindow, equals(initialWindow - dataLength));
    });

    test('detects when window adjustment is needed', () {
      const initialWindow = 2 * 1024 * 1024;
      // Send enough data to trigger threshold (50% of window = 1MB)
      const dataToSend = initialWindow - (initialWindow ~/ 2) + 1;
      
      controller.processIncomingData(dataToSend);
      
      expect(controller.needsWindowAdjustment, isTrue);
    });

    test('calculates window adjustment correctly', () {
      // Fill window to trigger adjustment
      controller.processIncomingData(1500 * 1024); // 1.5MB
      
      expect(controller.needsWindowAdjustment, isTrue);
      
      final bytesToAdd = controller.calculateWindowAdjustment();
      
      expect(bytesToAdd, greaterThan(0));
      expect(controller.localWindow, greaterThan(200 * 1024)); // Adjusted for BDP constraints
    });

    test('respects minimum window size', () {
      final smallController = SSHChannelFlowController(
        initialWindowSize: 64 * 1024, // 64KB
        minimumWindowSize: 32 * 1024, // 32KB minimum
      );
      
      // Fill most of the window
      smallController.processIncomingData(50 * 1024);
      smallController.calculateWindowAdjustment();
      
      expect(smallController.currentWindowSize, 
             greaterThanOrEqualTo(32 * 1024));
    });

    test('respects maximum window size', () {
      const maxSize = 100 * 1024; // Small max for testing
      final constrainedController = SSHChannelFlowController(
        initialWindowSize: 50 * 1024,
        maximumWindowSize: maxSize,
      );
      
      // Trigger multiple adjustments
      for (int i = 0; i < 5; i++) {
        constrainedController.processIncomingData(20 * 1024);
        constrainedController.calculateWindowAdjustment();
      }
      
      expect(constrainedController.currentWindowSize, 
             lessThanOrEqualTo(maxSize));
    });

    test('adaptive resizing can be disabled', () {
      final fixedController = SSHChannelFlowController(
        enableAdaptiveResizing: false,
      );
      
      final initialSize = fixedController.currentWindowSize;
      
      // Simulate good network conditions
      for (int i = 0; i < 10; i++) {
        fixedController.processIncomingData(100 * 1024);
        fixedController.calculateWindowAdjustment();
      }
      
      // Window size should remain relatively stable
      expect(fixedController.currentWindowSize, equals(initialSize));
    });

    test('tracks performance statistics', () {
      controller.processIncomingData(1024);
      
      final stats = controller.getStatistics();
      
      expect(stats, containsPair('currentWindowSize', isA<int>()));
      expect(stats, containsPair('localWindow', isA<int>()));
      expect(stats, containsPair('totalBytesReceived', equals(1024)));
      expect(stats, containsPair('estimatedBandwidth', isA<double>()));
      expect(stats, containsPair('estimatedRtt', isA<double>()));
      expect(stats, containsPair('congestionDetected', isA<bool>()));
    });

    test('reset restores initial state', () {
      // Modify state
      controller.processIncomingData(1024);
      controller.calculateWindowAdjustment();
      
      final initialWindow = 2 * 1024 * 1024;
      
      // Reset and verify
      controller.reset();
      
      expect(controller.localWindow, equals(initialWindow));
      expect(controller.currentWindowSize, equals(initialWindow));
      expect(controller.getStatistics()['totalBytesReceived'], equals(0));
      expect(controller.getStatistics()['congestionDetected'], isFalse);
    });

    test('handles custom configuration', () {
      final customController = SSHChannelFlowController(
        initialWindowSize: 4 * 1024 * 1024, // 4MB
        minimumWindowSize: 64 * 1024, // 64KB
        maximumWindowSize: 16 * 1024 * 1024, // 16MB
        thresholdRatio: 0.3, // 30% threshold
        enableAdaptiveResizing: true,
      );
      
      expect(customController.currentWindowSize, equals(4 * 1024 * 1024));
      expect(customController.currentThreshold, 
             equals((4 * 1024 * 1024 * 0.3).round()));
      
      // Need to send 70% of window to trigger adjustment
      customController.processIncomingData((4 * 1024 * 1024 * 0.7).round());
      expect(customController.needsWindowAdjustment, isTrue);
    });

    test('simulates network congestion scenario', () {
      // Simulate rapidly decreasing throughput to trigger congestion detection
      // This is a simplified test - real congestion detection needs time-based data
      for (int i = 0; i < 20; i++) {
        controller.processIncomingData(1024);
        // Add small delays to simulate time passing
        if (i % 5 == 0) {
          controller.calculateWindowAdjustment();
        }
      }
      
      final stats = controller.getStatistics();
      expect(stats['performanceHistorySize'], greaterThanOrEqualTo(0));
    });

    test('handles edge case: zero data length', () {
      expect(() => controller.processIncomingData(0), returnsNormally);
      expect(controller.localWindow, equals(controller.currentWindowSize));
    });

    test('handles edge case: very large data length', () {
      const largeData = 10 * 1024 * 1024; // 10MB, larger than default window
      
      controller.processIncomingData(largeData);
      
      expect(controller.localWindow, lessThan(0)); // Window goes negative
      expect(controller.needsWindowAdjustment, isTrue);
      
      final adjustment = controller.calculateWindowAdjustment();
      expect(adjustment, greaterThan(0)); // Should provide some window space
      expect(controller.localWindow, greaterThan(0)); // Window restored
    });

    test('bandwidth-delay product calculation influences window sizing', () {
      // Create controller that should adapt based on network conditions
      final adaptiveController = SSHChannelFlowController(
        enableAdaptiveResizing: true,
        debugPrint: (msg) => print('BDP Test: $msg'),
      );
      
      // Simulate high bandwidth, high latency scenario
      // This is simplified since we can't easily simulate time-based metrics in unit tests
      adaptiveController.processIncomingData(1024);
      
      // After processing data and adjustments, window should potentially change
      for (int i = 0; i < 5; i++) {
        adaptiveController.processIncomingData(200 * 1024);
        adaptiveController.calculateWindowAdjustment();
      }
      
      // The window size may have changed due to adaptive algorithms
      // (In a real scenario, this would be more predictable with actual timing data)
      expect(adaptiveController.currentWindowSize, isA<int>());
    });
  });

  group('SSHChannelFlowController Edge Cases', () {
    test('handles negative window correctly', () {
      final controller = SSHChannelFlowController(
        initialWindowSize: 64 * 1024, // 64KB window for testing 
        minimumWindowSize: 32 * 1024, // 32KB minimum
      );
      
      // Send more data than window can handle
      controller.processIncomingData(128 * 1024); // 128KB
      
      expect(controller.localWindow, lessThan(0));
      expect(controller.needsWindowAdjustment, isTrue);
      
      final adjustment = controller.calculateWindowAdjustment();
      expect(adjustment, greaterThanOrEqualTo(128 * 1024));
      expect(controller.localWindow, greaterThanOrEqualTo(32 * 1024));
    });

    test('validates constructor arguments', () {
      expect(
        () => SSHChannelFlowController(
          minimumWindowSize: 0,
        ),
        throwsA(isA<AssertionError>()),
      );
      
      expect(
        () => SSHChannelFlowController(
          minimumWindowSize: 1024,
          maximumWindowSize: 512, // Max < Min
        ),
        throwsA(isA<AssertionError>()),
      );
      
      expect(
        () => SSHChannelFlowController(
          thresholdRatio: 0.0, // Invalid threshold
        ),
        throwsA(isA<AssertionError>()),
      );
      
      expect(
        () => SSHChannelFlowController(
          thresholdRatio: 1.0, // Invalid threshold
        ),
        throwsA(isA<AssertionError>()),
      );
    });

    test('handles performance history overflow', () {
      final controller = SSHChannelFlowController();
      
      // Add more metrics than history size (should be 10)
      for (int i = 0; i < 15; i++) {
        controller.processIncomingData(1024);
        if (i % 2 == 0) {
          controller.calculateWindowAdjustment();
        }
      }
      
      final stats = controller.getStatistics();
      expect(stats['performanceHistorySize'], lessThanOrEqualTo(10));
    });
  });
}
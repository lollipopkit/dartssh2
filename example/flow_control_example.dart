// Example demonstrating enhanced SSH flow control features
// This example shows how to monitor and configure flow control in DartSSH2

import 'dart:typed_data';
import 'package:dartssh2/dartssh2.dart';

void main() async {
  // Example 1: Basic SSH connection with flow control monitoring
  await basicFlowControlExample();
  
  // Example 2: Advanced flow control configuration
  await advancedFlowControlExample();
}

/// Basic example showing flow control monitoring during SSH operations
Future<void> basicFlowControlExample() async {
  print('\n=== Basic Flow Control Example ===');
  
  try {
    final client = SSHClient(
      await SSHSocket.connect('localhost', 22),
      username: 'testuser',
      onPasswordRequest: () => 'password123',
    );

    final session = await client.shell();
    
    // Monitor flow control statistics
    final stats = session.getFlowControlStatistics();
    print('Initial flow control stats:');
    _printFlowControlStats(stats);
    
    // Send some data and monitor flow control changes
    session.stdin.add(Uint8List.fromList('echo "Testing flow control"\n'.codeUnits));
    
    // Wait for response and check stats again
    await Future.delayed(Duration(seconds: 1));
    final updatedStats = session.getFlowControlStatistics();
    print('\nUpdated flow control stats:');
    _printFlowControlStats(updatedStats);
    
    session.close();
    client.close();
    
  } catch (e) {
    print('Error in basic example: $e');
  }
}

/// Advanced example showing custom flow control configuration
Future<void> advancedFlowControlExample() async {
  print('\n=== Advanced Flow Control Configuration ===');
  
  try {
    // Create a client with custom flow control settings
    final client = SSHClient(
      await SSHSocket.connect('localhost', 22),
      username: 'testuser',
      onPasswordRequest: () => 'password123',
    );

    final session = await client.shell();
    
    print('Testing flow control under high load...');
    
    // Simulate high-throughput scenario
    final largeData = 'A' * 1024; // 1KB of data
    for (int i = 0; i < 100; i++) {
      session.stdin.add(Uint8List.fromList('echo "$largeData"\n'.codeUnits));
      
      // Periodically check flow control stats
      if (i % 20 == 0) {
        final stats = session.getFlowControlStatistics();
        print('Iteration $i - Flow control stats:');
        _printFlowControlStats(stats);
        
        // Check for congestion
        if (stats['congestionDetected'] == true) {
          print('  ⚠️  Congestion detected! Flow control is adapting...');
        }
      }
      
      // Small delay to prevent overwhelming
      await Future.delayed(Duration(milliseconds: 50));
    }
    
    // Final statistics
    print('\nFinal flow control statistics:');
    final finalStats = session.getFlowControlStatistics();
    _printFlowControlStats(finalStats);
    
    // Demonstrate flow control reset
    print('\nResetting flow control...');
    session.resetFlowControl();
    final resetStats = session.getFlowControlStatistics();
    print('After reset:');
    _printFlowControlStats(resetStats);
    
    session.close();
    client.close();
    
  } catch (e) {
    print('Error in advanced example: $e');
  }
}

/// Helper function to print flow control statistics in a readable format
void _printFlowControlStats(Map<String, dynamic> stats) {
  print('  Current Window Size: ${_formatBytes(stats['currentWindowSize'])}');
  print('  Available Window: ${_formatBytes(stats['localWindow'])}');
  print('  Window Threshold: ${_formatBytes(stats['threshold'])}');
  print('  Total Bytes Received: ${_formatBytes(stats['totalBytesReceived'])}');
  print('  Estimated Bandwidth: ${_formatBytes(stats['estimatedBandwidth'].round())}/s');
  print('  Estimated RTT: ${stats['estimatedRtt'].toStringAsFixed(1)}ms');
  print('  Average Throughput: ${_formatBytes(stats['averageThroughput'].round())}/s');
  print('  Congestion Detected: ${stats['congestionDetected']}');
  print('  Performance History: ${stats['performanceHistorySize']} entries');
}

/// Helper function to format bytes in human-readable format
String _formatBytes(int bytes) {
  if (bytes < 1024) return '${bytes}B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
  if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)}GB';
}

/// Example of creating a custom flow controller (for advanced users)
void customFlowControllerExample() {
  print('\n=== Custom Flow Controller Example ===');
  
  // Create a flow controller with custom parameters
  final customFlowController = SSHChannelFlowController(
    initialWindowSize: 4 * 1024 * 1024, // 4MB initial window
    minimumWindowSize: 64 * 1024,       // 64KB minimum
    maximumWindowSize: 32 * 1024 * 1024, // 32MB maximum  
    thresholdRatio: 0.3,                 // Trigger adjustment at 30% remaining
    enableAdaptiveResizing: true,        // Enable intelligent window sizing
    debugPrint: (message) => print('FlowControl: $message'),
  );
  
  // Simulate data processing
  customFlowController.processIncomingData(1024 * 1024); // 1MB
  
  if (customFlowController.needsWindowAdjustment) {
    final adjustment = customFlowController.calculateWindowAdjustment();
    print('Window adjustment needed: ${_formatBytes(adjustment)}');
  }
  
  // Get performance statistics
  final stats = customFlowController.getStatistics();
  print('Custom controller stats:');
  _printFlowControlStats(stats);
}
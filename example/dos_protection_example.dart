import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/security/ssh_dos_protection.dart';

/// Example demonstrating advanced DoS protection with DartSSH2
Future<void> main() async {
  // Create a shared DoS protection instance for multiple connections
  final dosProtection = SSHDoSProtection();
  
  try {
    print('Connecting to SSH server with DoS protection enabled...');
    
    final socket = await SSHSocket.connect('localhost', 22);
    
    final client = SSHClient(
      socket,
      username: 'user',
      enableDoSProtection: true,
      dosProtection: dosProtection, // Use shared instance
      onPasswordRequest: () => 'password',
    );

    // Print initial DoS protection statistics
    print('Initial DoS protection stats:');
    print(client.getDoSStatistics());

    try {
      // Execute a command
      final session = await client.execute('echo "Hello from protected SSH!"');
      
      // Listen to output
      await for (final data in session.stdout) {
        print('STDOUT: ${String.fromCharCodes(data)}');
      }

      await for (final data in session.stderr) {
        print('STDERR: ${String.fromCharCodes(data)}');
      }

      print('Exit code: ${session.exitCode}');
      
      // Print final statistics
      print('Final DoS protection stats:');
      print(client.getDoSStatistics());
      
    } catch (e) {
      print('Error: $e');
      
      // Check if it's a DoS protection error
      if (e.toString().contains('DoS protection')) {
        print('Connection blocked by DoS protection');
      }
    } finally {
      client.close();
    }
    
  } catch (e) {
    print('Connection error: $e');
    
    // Check if it's a DoS protection error
    if (e.toString().contains('DoS protection')) {
      print('Connection blocked by DoS protection');
      print('This could be due to:');
      print('- Too many connections from this host');
      print('- Too many connection attempts in a short time');
      print('- Too many authentication attempts');
      print('- Exceeding rate limits');
    }
  } finally {
    // Clean up the shared DoS protection instance
    dosProtection.dispose();
  }
}

/// Example of DoS protection limits and what they mean:
/// 
/// Connection Limits:
/// - maxConnectionsPerHost: 5 connections per remote host
/// - maxTotalConnections: 50 total connections
/// - connectionsPerMinute: 10 connections per minute per host
/// 
/// Authentication Limits:
/// - authAttemptsPerMinute: 5 authentication attempts per minute per host
/// 
/// Rate Limits:
/// - packetsPerSecond: 1000 packets per second per connection
/// - maxMemoryPerConnection: 50MB per connection
/// 
/// These limits help prevent:
/// - Connection flooding attacks
/// - Brute force authentication attacks
/// - Resource exhaustion attacks
/// - Packet flooding attacks
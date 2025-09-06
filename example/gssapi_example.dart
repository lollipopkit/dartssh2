import 'dart:async';
import 'dart:typed_data';
import 'package:dartssh2/dartssh2.dart';

/// Example demonstrating GSSAPI authentication with DartSSH2
/// 
/// This example shows how to use the GSSAPI authentication method
/// for enterprise environments that support Kerberos authentication.
Future<void> main() async {
  // Example GSSAPI credentials
  final gssapiCredentials = SSHGSSAPICredentials(
    serviceName: 'host@server.example.com',
    mechanismOids: [
      '1.2.840.113554.1.2.2', // Kerberos OID
      '1.3.6.1.5.5.2',       // SPNEGO OID
    ],
    delegationRequested: true,
    mutualAuthentication: true,
  );

  // Create SSH client with GSSAPI authentication support
  final client = SSHClient(
    await SSHSocket.connect('server.example.com', 22),
    username: 'user',
    
    // GSSAPI authentication handler
    onGSSAPIRequest: (supportedMechanisms) async {
      print('Server supports GSSAPI mechanisms: $supportedMechanisms');
      
      // Return the GSSAPI credentials to use
      return gssapiCredentials;
    },
    
    // GSSAPI token exchange handler
    onGSSAPIToken: (token) async {
      print('Received GSSAPI token (${token.length} bytes)');
      
      // In a real implementation, this would use a GSSAPI library
      // to process the token and generate a response
      // For this example, we'll return null to skip to next method
      return null;
    },
    
    // Fallback to password authentication if GSSAPI fails
    onPasswordRequest: () async {
      print('Falling back to password authentication');
      return 'your-password';
    },
  );

  try {
    // Connect and authenticate
    await client.authenticated;
    print('Successfully authenticated using GSSAPI or fallback method');
    
    // Close the connection
    client.close();
  } catch (e) {
    print('Authentication failed: $e');
    client.close();
  }
}

/// Example of a more advanced GSSAPI implementation
class AdvancedGSSAPIExample {
  /// Simulated GSSAPI context
  static Future<Uint8List?> simulateGSSAPITokenExchange(
    Uint8List token, {
    required String targetName,
    required List<String> mechanismOids,
  }) async {
    // In a real implementation, this would use a GSSAPI library
    // like the MIT Kerberos library or a platform-specific GSSAPI implementation
    
    print('Simulating GSSAPI token exchange for target: $targetName');
    print('Using mechanisms: $mechanismOids');
    print('Received token length: ${token.length} bytes');
    
    // Simulate token processing
    if (token.isEmpty) {
      // Initial token - return simulated context token
      return Uint8List.fromList([0x60, 0x06, 0x06, 0x01, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
    } else {
      // Subsequent token - return null to indicate completion
      return null;
    }
  }
  
  /// Example usage with advanced token handling
  static Future<void> advancedExample() async {
    final client = SSHClient(
      await SSHSocket.connect('server.example.com', 22),
      username: 'user',
      
      onGSSAPIRequest: (supportedMechanisms) async {
        print('Server GSSAPI mechanisms: $supportedMechanisms');
        
        // Filter to supported mechanisms
        final supportedOids = supportedMechanisms.where((oid) => 
          oid == '1.2.840.113554.1.2.2' || // Kerberos
          oid == '1.3.6.1.5.5.2'          // SPNEGO
        ).toList();
        
        if (supportedOids.isEmpty) {
          return null; // No supported mechanisms
        }
        
        return SSHGSSAPICredentials(
          serviceName: 'host@server.example.com',
          mechanismOids: supportedOids,
          delegationRequested: false,
          mutualAuthentication: true,
        );
      },
      
      onGSSAPIToken: (token) async {
        return await simulateGSSAPITokenExchange(
          token,
          targetName: 'host@server.example.com',
          mechanismOids: ['1.2.840.113554.1.2.2'],
        );
      },
    );
    
    try {
      await client.authenticated;
      print('GSSAPI authentication successful');
      
      client.close();
    } catch (e) {
      print('GSSAPI authentication failed: $e');
      client.close();
    }
  }
}
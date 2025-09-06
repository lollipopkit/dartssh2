import 'dart:io';
import 'package:dartssh2/dartssh2.dart';

/// Example demonstrating enhanced security policies for authentication method prioritization
void main() async {
  // Example 1: Security-focused policy (requires public key, allows password as fallback)
  final securityPolicy = SSHAuthPolicy.securityFocused(
    requirePublicKey: false, // Don't require, but prioritize public key
    allowPassword: true,    // Allow password as fallback
  );

  // Example 2: Compatibility-focused policy (supports older servers)
  final compatibilityPolicy = SSHAuthPolicy.compatibilityFocused();

  // Example 3: Custom policy with specific method order and priorities
  final customPolicy = SSHAuthPolicy(
    methodOrder: [
      SSHAuthMethod.publicKey,
      SSHAuthMethod.keyboardInteractive,
      SSHAuthMethod.password,
    ],
    strictMode: false,
    minSecurityLevel: SSHSecurityLevel.standard,
    methodPriorities: {
      SSHAuthMethod.publicKey: 100,
      SSHAuthMethod.keyboardInteractive: 85,
      SSHAuthMethod.password: 60,
      SSHAuthMethod.hostbased: 90,
      SSHAuthMethod.none: 10,
    },
  );

  // Example 4: High-security policy (strict mode, only allows strong methods)
  final highSecurityPolicy = SSHAuthPolicy(
    methodOrder: [
      SSHAuthMethod.publicKey,
      SSHAuthMethod.hostbased,
    ],
    strictMode: true,
    minSecurityLevel: SSHSecurityLevel.high,
    methodPriorities: {
      SSHAuthMethod.publicKey: 100,
      SSHAuthMethod.hostbased: 95,
      SSHAuthMethod.keyboardInteractive: 75,
      SSHAuthMethod.password: 50,
      SSHAuthMethod.none: 10,
    },
  );

  // Connect to SSH server with security policy
  final socket = await SSHSocket.connect('example.com', 22);
  final client = SSHClient(
    socket,
    username: 'user',
    identities: [
      // Load your private keys here
      // SSHKeyPair.fromPem(await File('private_key.pem').readAsString()),
    ],
    onPasswordRequest: () {
      print('Password requested');
      return 'password'; // In real app, get password securely
    },
    authPolicy: securityPolicy, // Apply the security policy
    printDebug: print,
  );

  try {
    await client.authenticated;
    print('Authentication successful with policy: ${client.authPolicy?.runtimeType}');
    
    // Show security information about used methods
    if (client.authPolicy != null) {
      print('Security level requirements: ${client.authPolicy!.minSecurityLevel}');
      print('Method priorities:');
      for (final method in SSHAuthMethod.values) {
        final priority = client.authPolicy!.getMethodPriority(method);
        final securityInfo = SSHAuthMethodSecurity.securityInfo[method];
        print('  ${method.name}: priority=$priority, level=${securityInfo?.securityLevel}');
      }
    }
    
    // Use the connection...
    final session = await client.execute('echo "Hello from DartSSH2 with security policy!"');
    print(session.stdout);
    
  } catch (e) {
    print('Authentication failed: $e');
  } finally {
    client.close();
  }
}

/// Example showing different security scenarios
class SecurityPolicyExamples {
  /// High-security environment (banking, healthcare)
  static SSHAuthPolicy get highSecurity => SSHAuthPolicy.securityFocused(
    requirePublicKey: true,
    allowPassword: false,
  );

  /// Enterprise environment (balanced security and usability)
  static SSHAuthPolicy get enterprise => SSHAuthPolicy(
    methodOrder: [
      SSHAuthMethod.publicKey,
      SSHAuthMethod.keyboardInteractive,
      SSHAuthMethod.password,
    ],
    strictMode: false,
    minSecurityLevel: SSHSecurityLevel.high,
    methodPriorities: {
      SSHAuthMethod.publicKey: 100,
      SSHAuthMethod.keyboardInteractive: 85,
      SSHAuthMethod.password: 70,
      SSHAuthMethod.hostbased: 90,
      SSHAuthMethod.none: 10,
    },
  );

  /// Development environment (convenience over security)
  static SSHAuthPolicy get development => SSHAuthPolicy.compatibilityFocused();

  /// Legacy system support (max compatibility)
  static SSHAuthPolicy get legacy => SSHAuthPolicy(
    methodOrder: [
      SSHAuthMethod.password,
      SSHAuthMethod.publicKey,
      SSHAuthMethod.keyboardInteractive,
    ],
    strictMode: false,
    minSecurityLevel: SSHSecurityLevel.low,
    methodPriorities: {
      SSHAuthMethod.password: 90,
      SSHAuthMethod.publicKey: 85,
      SSHAuthMethod.keyboardInteractive: 80,
      SSHAuthMethod.hostbased: 75,
      SSHAuthMethod.none: 10,
    },
  );
}
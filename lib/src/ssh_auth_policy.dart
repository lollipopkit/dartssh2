import 'ssh_userauth.dart';

/// Security policy for authentication method prioritization
class SSHAuthPolicy {
  /// Default authentication method order (most secure first)
  static const List<SSHAuthMethod> _defaultMethodOrder = [
    SSHAuthMethod.certificate,
    SSHAuthMethod.publicKey,
    SSHAuthMethod.hostbased,
    SSHAuthMethod.keyboardInteractive,
    SSHAuthMethod.password,
  ];

  /// Custom authentication method order
  final List<SSHAuthMethod> methodOrder;

  /// Whether to enable strict mode (only allow methods in the specified order)
  final bool strictMode;

  /// Minimum required security level for authentication
  final SSHSecurityLevel minSecurityLevel;

  /// Authentication method priorities (higher number = higher priority)
  final Map<SSHAuthMethod, int> methodPriorities;

  /// Creates a new authentication policy
  SSHAuthPolicy({
    List<SSHAuthMethod>? methodOrder,
    this.strictMode = false,
    this.minSecurityLevel = SSHSecurityLevel.standard,
    Map<SSHAuthMethod, int>? methodPriorities,
  })  : methodOrder = methodOrder ?? _defaultMethodOrder,
        methodPriorities = methodPriorities ?? {
          SSHAuthMethod.certificate: 120,
          SSHAuthMethod.publicKey: 100,
          SSHAuthMethod.hostbased: 90,
          SSHAuthMethod.keyboardInteractive: 80,
          SSHAuthMethod.password: 70,
          SSHAuthMethod.none: 10,
        };

  /// Creates a security-focused policy (prioritizes stronger methods)
  factory SSHAuthPolicy.securityFocused({
    bool requirePublicKey = false,
    bool allowPassword = true,
  }) {
    final order = <SSHAuthMethod>[];
    final priorities = <SSHAuthMethod, int>{};

    if (requirePublicKey) {
      order.addAll([SSHAuthMethod.certificate, SSHAuthMethod.publicKey]);
      priorities[SSHAuthMethod.certificate] = 120;
      priorities[SSHAuthMethod.publicKey] = 100;
    } else {
      order.addAll([
        SSHAuthMethod.certificate,
        SSHAuthMethod.publicKey,
        SSHAuthMethod.hostbased,
        SSHAuthMethod.keyboardInteractive,
      ]);
      priorities.addAll({
        SSHAuthMethod.certificate: 120,
        SSHAuthMethod.publicKey: 100,
        SSHAuthMethod.hostbased: 90,
        SSHAuthMethod.keyboardInteractive: 80,
      });
    }

    if (allowPassword) {
      order.add(SSHAuthMethod.password);
      priorities[SSHAuthMethod.password] = 70;
    }

    priorities[SSHAuthMethod.none] = 10;

    return SSHAuthPolicy(
      methodOrder: order,
      strictMode: requirePublicKey,
      minSecurityLevel: SSHSecurityLevel.high,
      methodPriorities: priorities,
    );
  }

  /// Creates a compatibility-focused policy (allows weaker methods for compatibility)
  factory SSHAuthPolicy.compatibilityFocused() {
    return SSHAuthPolicy(
      methodOrder: [
        SSHAuthMethod.certificate,
        SSHAuthMethod.publicKey,
        SSHAuthMethod.password,
        SSHAuthMethod.keyboardInteractive,
        SSHAuthMethod.hostbased,
      ],
      strictMode: false,
      minSecurityLevel: SSHSecurityLevel.standard,
      methodPriorities: {
        SSHAuthMethod.certificate: 110,
        SSHAuthMethod.publicKey: 90,
        SSHAuthMethod.password: 85,
        SSHAuthMethod.keyboardInteractive: 80,
        SSHAuthMethod.hostbased: 75,
        SSHAuthMethod.none: 10,
      },
    );
  }

  /// Sorts authentication methods according to this policy
  List<SSHAuthMethod> sortMethods(List<SSHAuthMethod> availableMethods) {
    if (strictMode) {
      // In strict mode, only use methods that are in our preferred order
      final filtered = availableMethods.where((method) => methodOrder.contains(method)).toList();
      return filtered
          .map((method) => (method, methodPriorities[method] ?? 0))
          .where((pair) => pair.$2 >= minSecurityLevel.value)
          .toList()
          .reversed
          .map((pair) => pair.$1)
          .toList();
    }

    // In non-strict mode, sort all available methods by priority
    return availableMethods
        .map((method) => (method, methodPriorities[method] ?? 50))
        .where((pair) => pair.$2 >= minSecurityLevel.value)
        .toList()
        .reversed
        .map((pair) => pair.$1)
        .toList();
  }

  /// Gets the priority of a specific authentication method
  int getMethodPriority(SSHAuthMethod method) {
    return methodPriorities[method] ?? 50;
  }

  /// Checks if a method meets the minimum security level
  bool meetsSecurityRequirements(SSHAuthMethod method) {
    return getMethodPriority(method) >= minSecurityLevel.value;
  }
}

/// Security levels for authentication methods
enum SSHSecurityLevel {
  none(0),
  low(25),
  standard(50),
  high(75),
  maximum(100);

  const SSHSecurityLevel(this.value);
  final int value;
}

/// Authentication method security information
class SSHAuthMethodSecurity {
  final SSHAuthMethod method;
  final SSHSecurityLevel securityLevel;
  final String description;
  final List<String> securityConsiderations;

  const SSHAuthMethodSecurity({
    required this.method,
    required this.securityLevel,
    required this.description,
    required this.securityConsiderations,
  });

  /// Security information for all authentication methods
  static const Map<SSHAuthMethod, SSHAuthMethodSecurity> securityInfo = {
    SSHAuthMethod.certificate: SSHAuthMethodSecurity(
      method: SSHAuthMethod.certificate,
      securityLevel: SSHSecurityLevel.maximum,
      description: 'Certificate-based authentication using X.509 or OpenSSH certificates',
      securityConsiderations: [
        'Most secure authentication method with PKI infrastructure',
        'Supports certificate revocation and lifecycle management',
        'Enables centralized trust management',
        'Provides strong identity verification with expiration dates',
        'Supports X.509 v3 and OpenSSH certificate formats',
      ],
    ),
    SSHAuthMethod.publicKey: SSHAuthMethodSecurity(
      method: SSHAuthMethod.publicKey,
      securityLevel: SSHSecurityLevel.maximum,
      description: 'Public key authentication using cryptographic keys',
      securityConsiderations: [
        'Most secure authentication method',
        'Requires private key protection',
        'Supports various key types (RSA, ECDSA, Ed25519)',
        'Resistant to password guessing attacks',
      ],
    ),
    SSHAuthMethod.hostbased: SSHAuthMethodSecurity(
      method: SSHAuthMethod.hostbased,
      securityLevel: SSHSecurityLevel.high,
      description: 'Host-based authentication using client host keys',
      securityConsiderations: [
        'High security when properly configured',
        'Requires secure client host configuration',
        'Depends on host key security',
        'Not commonly used in general SSH scenarios',
      ],
    ),
    SSHAuthMethod.keyboardInteractive: SSHAuthMethodSecurity(
      method: SSHAuthMethod.keyboardInteractive,
      securityLevel: SSHSecurityLevel.standard,
      description: 'Interactive authentication with multiple prompts',
      securityConsiderations: [
        'Flexible authentication method',
        'Can support multi-factor authentication',
        'Security depends on the specific implementation',
        'May be vulnerable to phishing if not implemented carefully',
      ],
    ),
    SSHAuthMethod.password: SSHAuthMethodSecurity(
      method: SSHAuthMethod.password,
      securityLevel: SSHSecurityLevel.low,
      description: 'Password-based authentication',
      securityConsiderations: [
        'Least secure authentication method',
        'Vulnerable to password guessing attacks',
        'Requires strong password policies',
        'Should only be used over encrypted connections',
      ],
    ),
    SSHAuthMethod.none: SSHAuthMethodSecurity(
      method: SSHAuthMethod.none,
      securityLevel: SSHSecurityLevel.none,
      description: 'No authentication (for method discovery)',
      securityConsiderations: [
        'Not a real authentication method',
        'Used only for discovering supported methods',
        'Should never be used for actual authentication',
      ],
    ),
  };
}
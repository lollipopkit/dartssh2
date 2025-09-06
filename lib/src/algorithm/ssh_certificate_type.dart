import 'dart:typed_data';
import 'package:dartssh2/src/ssh_algorithm.dart';

/// SSH certificate types supported by the library
enum SSHCertificateType {
  /// X.509 v3 certificates (RFC 6187)
  x509v3('x509v3@openssh.com'),
  
  /// OpenSSH certificate format
  openssh('ssh-cert-v01@openssh.com'),
  
  /// No certificate
  none('none');

  const SSHCertificateType(this.name);

  final String name;

  static SSHCertificateType? fromName(String name) {
    for (final type in values) {
      if (type.name == name) {
        return type;
      }
    }
    return null;
  }
}

/// Base class for SSH certificate types
abstract class SSHCertificateTypeBase with SSHAlgorithm {
  @override
  final String name;

  SSHCertificateTypeBase(this.name);

  /// Creates a certificate type from the given name
  static SSHCertificateTypeBase? fromName(String name) {
    return SSHCertificateType.fromName(name)?.toBase();
  }

  /// Validates the certificate format
  bool isValidCertificateFormat(Uint8List data);

  /// Extracts the public key from the certificate
  Uint8List extractPublicKey(Uint8List data);
}

/// X.509 v3 certificate implementation
class SSHX509Certificate extends SSHCertificateTypeBase {
  SSHX509Certificate() : super(SSHCertificateType.x509v3.name);

  @override
  bool isValidCertificateFormat(Uint8List data) {
    // Basic X.509 certificate validation
    if (data.length < 4) return false;
    
    // Check for X.509 certificate structure (starts with SEQUENCE tag)
    if (data[0] != 0x30) return false;
    
    // Validate certificate structure
    try {
      // TODO: Implement proper X.509 certificate parsing
      return true;
    } catch (e) {
      return false;
    }
  }

  @override
  Uint8List extractPublicKey(Uint8List data) {
    // TODO: Implement X.509 public key extraction
    throw UnimplementedError('X.509 public key extraction not yet implemented');
  }
}

/// OpenSSH certificate implementation
class SSHOpenSSHCertificate extends SSHCertificateTypeBase {
  SSHOpenSSHCertificate() : super(SSHCertificateType.openssh.name);

  @override
  bool isValidCertificateFormat(Uint8List data) {
    // Basic OpenSSH certificate validation
    if (data.length < 8) return false;
    
    // Check for OpenSSH certificate signature
    // TODO: Implement proper OpenSSH certificate validation
    return true;
  }

  @override
  Uint8List extractPublicKey(Uint8List data) {
    // TODO: Implement OpenSSH public key extraction
    throw UnimplementedError('OpenSSH public key extraction not yet implemented');
  }
}

extension SSHCertificateTypeExtension on SSHCertificateType {
  SSHCertificateTypeBase toBase() {
    switch (this) {
      case SSHCertificateType.x509v3:
        return SSHX509Certificate();
      case SSHCertificateType.openssh:
        return SSHOpenSSHCertificate();
      case SSHCertificateType.none:
        throw ArgumentError('Cannot convert "none" certificate type to base');
    }
  }
}
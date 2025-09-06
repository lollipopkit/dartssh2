import 'package:dartssh2/src/algorithm/ssh_certificate_type.dart';
import 'package:dartssh2/src/ssh_key_pair.dart';

/// Certificate validation utilities for SSH certificate authentication
class SSHCertificateValidator {
  /// Validates a certificate against various criteria
  static bool validateCertificate(SSHCertificate certificate, {
    DateTime? currentTime,
    List<String>? allowedIssuers,
    List<String>? allowedSubjects,
    bool requireValidTime = true,
  }) {
    // Basic certificate validation
    if (!certificate.isValid(currentTime)) {
      return false;
    }
    
    // Check if certificate is not expired
    if (requireValidTime) {
      final now = currentTime ?? DateTime.now();
      if (certificate.notValidBefore != null && now.isBefore(certificate.notValidBefore!)) {
        return false;
      }
      if (certificate.notValidAfter != null && now.isAfter(certificate.notValidAfter!)) {
        return false;
      }
    }
    
    // Check issuer restrictions
    if (allowedIssuers != null && allowedIssuers.isNotEmpty) {
      if (certificate.issuer == null || !allowedIssuers.contains(certificate.issuer)) {
        return false;
      }
    }
    
    // Check subject restrictions
    if (allowedSubjects != null && allowedSubjects.isNotEmpty) {
      if (certificate.subject == null || !allowedSubjects.contains(certificate.subject)) {
        return false;
      }
    }
    
    return true;
  }
  
  /// Validates certificate chain (placeholder for future implementation)
  static bool validateCertificateChain(List<SSHCertificate> chain, {
    DateTime? currentTime,
    bool requireTrustedRoot = true,
  }) {
    if (chain.isEmpty) {
      return false;
    }
    
    // Validate each certificate in the chain
    for (int i = 0; i < chain.length; i++) {
      final cert = chain[i];
      
      // Validate the certificate itself
      if (!validateCertificate(cert, currentTime: currentTime)) {
        return false;
      }
      
      // TODO: Implement chain validation logic
      // - Check that each certificate is signed by the next one
      // - Validate that the root certificate is trusted
      // - Check for certificate revocation
    }
    
    return true;
  }
  
  /// Extracts certificate information for debugging/logging
  static Map<String, dynamic> getCertificateInfo(SSHCertificate certificate) {
    return {
      'type': certificate.certificateType.name,
      'subject': certificate.subject,
      'issuer': certificate.issuer,
      'notValidBefore': certificate.notValidBefore?.toIso8601String(),
      'notValidAfter': certificate.notValidAfter?.toIso8601String(),
      'isValid': certificate.isValid(),
      'certificateSize': certificate.certificateData.length,
    };
  }
  
  /// Checks if a certificate is suitable for SSH authentication
  static bool isSuitableForSSH(SSHCertificate certificate) {
    // Check if certificate type is supported for SSH
    if (certificate.certificateType == SSHCertificateType.none) {
      return false;
    }
    
    // Basic validity check
    if (!certificate.isValid()) {
      return false;
    }
    
    // Check if certificate has required fields
    if (certificate.subject == null) {
      return false;
    }
    
    // TODO: Add more specific SSH certificate validation
    // - Check for SSH-specific extensions
    // - Validate certificate purpose
    
    return true;
  }
  
  /// Creates a validation error message for debugging
  static String getValidationError(SSHCertificate certificate, {
    DateTime? currentTime,
    List<String>? allowedIssuers,
    List<String>? allowedSubjects,
  }) {
    final errors = <String>[];
    
    if (!certificate.isValid(currentTime)) {
      errors.add('Certificate is invalid');
    }
    
    final now = currentTime ?? DateTime.now();
    if (certificate.notValidBefore != null && now.isBefore(certificate.notValidBefore!)) {
      errors.add('Certificate is not yet valid (valid from ${certificate.notValidBefore})');
    }
    
    if (certificate.notValidAfter != null && now.isAfter(certificate.notValidAfter!)) {
      errors.add('Certificate has expired (expired at ${certificate.notValidAfter})');
    }
    
    if (allowedIssuers != null && 
        allowedIssuers.isNotEmpty && 
        (certificate.issuer == null || !allowedIssuers.contains(certificate.issuer))) {
      errors.add('Certificate issuer "${certificate.issuer}" is not in allowed issuers list');
    }
    
    if (allowedSubjects != null && 
        allowedSubjects.isNotEmpty && 
        (certificate.subject == null || !allowedSubjects.contains(certificate.subject))) {
      errors.add('Certificate subject "${certificate.subject}" is not in allowed subjects list');
    }
    
    if (!isSuitableForSSH(certificate)) {
      errors.add('Certificate is not suitable for SSH authentication');
    }
    
    return errors.isEmpty ? 'Certificate is valid' : 'Validation errors: ${errors.join(", ")}';
  }
}

/// Certificate revocation list manager (placeholder for future implementation)
class SSHCertificateRevocationList {
  final Set<String> _revokedCertificates = {};
  
  /// Adds a certificate to the revocation list
  void addRevokedCertificate(String certificateId) {
    _revokedCertificates.add(certificateId);
  }
  
  /// Removes a certificate from the revocation list
  void removeRevokedCertificate(String certificateId) {
    _revokedCertificates.remove(certificateId);
  }
  
  /// Checks if a certificate is revoked
  bool isRevoked(String certificateId) {
    return _revokedCertificates.contains(certificateId);
  }
  
  /// Gets the number of revoked certificates
  int get revokedCount => _revokedCertificates.length;
  
  /// Clears all revoked certificates
  void clear() {
    _revokedCertificates.clear();
  }
}
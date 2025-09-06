import 'dart:async';
import 'dart:typed_data';

enum SSHAuthMethod {
  none,
  password,
  publicKey,
  keyboardInteractive,
  hostbased,
  certificate,
  gssapi,
}

extension SSHAuthMethodX on SSHAuthMethod {
  String get name {
    switch (this) {
      case SSHAuthMethod.none:
        return 'none';
      case SSHAuthMethod.password:
        return 'password';
      case SSHAuthMethod.publicKey:
        return 'publickey';
      case SSHAuthMethod.keyboardInteractive:
        return 'keyboard-interactive';
      case SSHAuthMethod.hostbased:
        return 'hostbased';
      case SSHAuthMethod.certificate:
        return 'publickey'; // Certificate auth uses publickey method with certificate
      case SSHAuthMethod.gssapi:
        return 'gssapi-with-mic';
    }
  }
}

class SSHUserInfoRequest {
  SSHUserInfoRequest(this.name, this.instruction, this.prompts);

  /// Name of the request. For example, ""Password Expired".
  final String name;

  /// Instructions for the user. For example, "Please enter your password."
  final String instruction;

  /// List of prompts.
  final List<SSHUserInfoPrompt> prompts;
}

class SSHUserInfoPrompt {
  SSHUserInfoPrompt(this.promptText, this.echo);

  /// The prompt string. For example, "Password: ".
  final String promptText;

  /// Indicates whether or not the user input should be echoed as characters are typed.
  final bool echo;

  @override
  String toString() => '$runtimeType(prompt: $promptText, echo: $echo)';
}

class SSHChangePasswordResponse {
  SSHChangePasswordResponse(this.oldPassword, this.newPassword);

  /// Old password of the user.
  final String oldPassword;

  /// New password of the user.
  final String newPassword;
}

/// GSSAPI authentication context
class SSHGSSAPICredentials {
  SSHGSSAPICredentials({
    required this.serviceName,
    required this.mechanismOids,
    this.delegationRequested = false,
    this.mutualAuthentication = true,
  });

  /// Target service name (e.g., 'host@server.example.com')
  final String serviceName;
  
  /// List of supported GSSAPI mechanism OIDs
  final List<String> mechanismOids;
  
  /// Whether credential delegation is requested
  final bool delegationRequested;
  
  /// Whether mutual authentication is required
  final bool mutualAuthentication;
}

/// GSSAPI authentication handler
typedef SSHGSSAPIRequestHandler = FutureOr<SSHGSSAPICredentials?> Function(
  List<String> supportedMechanisms,
);

/// GSSAPI token exchange handler
typedef SSHGSSAPITokenHandler = FutureOr<Uint8List?> Function(
  Uint8List token,
);

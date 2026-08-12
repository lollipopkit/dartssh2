enum SSHAuthMethod {
  none,
  password,
  publicKey,
  keyboardInteractive,
  hostbased,
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

/// Which of the methods the server says may continue this client can act on.
///
/// The server lists the methods it has *enabled*, not the ones this client has
/// yet to use — that is ordinary OpenSSH behaviour. So every answer here asks
/// what is left rather than what was configured: a client that has offered
/// every key it has and answers "publickey" once more queues a method with
/// nothing to perform it with, and whatever pops the next key finds an empty
/// queue.
///
/// Order follows the server's list, since that is the order the server would
/// rather be asked in.
///
/// Pure, and outside [SSHClient], because the question is about state and not
/// about the socket — which is what makes it answerable in a test.
List<SSHAuthMethod> continuableAuthMethods({
  required Iterable<String> serverMethods,

  /// Whether any key remains that has not been offered yet.
  required bool hasUntriedKeys,

  /// The same, for host-based keys.
  required bool hasUntriedHostbasedKeys,

  /// Whether there is somewhere to get a password from.
  required bool canSupplyPassword,

  /// Whether there is somewhere to answer an information request from.
  required bool canAnswerUserInfo,

  /// Whether the client knows the host name and account that host-based
  /// authentication has to name.
  required bool hasHostbasedIdentity,

  /// Told about anything the server said that this client could not use.
  void Function(String message)? onNote,
}) {
  final methods = <SSHAuthMethod>[];

  for (final name in serverMethods) {
    switch (name) {
      case 'publickey':
        if (hasUntriedKeys) methods.add(SSHAuthMethod.publicKey);
        break;
      case 'password':
        if (canSupplyPassword) methods.add(SSHAuthMethod.password);
        break;
      case 'keyboard-interactive':
        if (canAnswerUserInfo) methods.add(SSHAuthMethod.keyboardInteractive);
        break;
      case 'hostbased':
        if (hasUntriedHostbasedKeys && hasHostbasedIdentity) {
          methods.add(SSHAuthMethod.hostbased);
        }
        break;
      case 'none':
        // RFC 4252: a server should not list this as one that can continue.
        onNote?.call('Warning: Server listed "none" as supported method');
        break;
      default:
        onNote?.call('Unknown authentication method from server: $name');
    }
  }

  return methods;
}

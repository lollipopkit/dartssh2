// ignore_for_file: camel_case_types, constant_identifier_names

part of 'base.dart';

/// SSH Authentication Protocol message numbers as defined in RFC 4252
abstract class SSHUserAuthMessageNumbers {
  /// General authentication message codes (RFC 4252 Section 6)
  static const int SSH_MSG_USERAUTH_REQUEST = 50;
  static const int SSH_MSG_USERAUTH_FAILURE = 51;
  static const int SSH_MSG_USERAUTH_SUCCESS = 52;
  static const int SSH_MSG_USERAUTH_BANNER = 53;

  /// Method-specific message numbers (RFC 4252 Section 6)
  /// Range 60-79 reserved for method-specific messages
  static const int SSH_MSG_USERAUTH_PK_OK = 60;
  static const int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
  static const int SSH_MSG_USERAUTH_INFO_REQUEST = 60;
  static const int SSH_MSG_USERAUTH_INFO_RESPONSE = 61;
  
  /// GSSAPI-specific message numbers (RFC 4462 Section 3)
  static const int SSH_MSG_USERAUTH_GSSAPI_RESPONSE = 60;
  static const int SSH_MSG_USERAUTH_GSSAPI_TOKEN = 61;
  static const int SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63;
  static const int SSH_MSG_USERAUTH_GSSAPI_ERROR = 64;
  static const int SSH_MSG_USERAUTH_GSSAPI_ERRTOK = 65;
  static const int SSH_MSG_USERAUTH_GSSAPI_MIC = 66;

  /// Validate message number is in correct range
  static bool isValidAuthMessageId(int messageId) {
    return (messageId >= 50 && messageId <= 53) || (messageId >= 60 && messageId <= 79);
  }
}

class SSH_Message_Userauth_Request extends SSHMessage {
  /// 50
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_REQUEST;

  final String user;
  final String serviceName;
  final String methodName;

  /* 'password' method specific fields */

  final String? oldPassword;
  final String? password;

  /* 'publickey' method specific fields */

  final String? publicKeyAlgorithm;
  final Uint8List? publicKey;
  final Uint8List? signature;

  /* 'publickey' method specific fields */

  final String? languageTag;
  final String? submethods;

  /* 'hostbased' method specific fields */

  final String? hostKeyAlgorithm;
  final Uint8List? hostKey;
  final String? hostName;
  final String? userNameOnClientHost;

  /* 'gssapi' method specific fields */

  final List<String>? gssapiMechanismOids;
  final Uint8List? gssapiToken;
  final Uint8List? gssapiMic;

  SSH_Message_Userauth_Request({
    required this.user,
    required this.serviceName,
    required this.methodName,
    this.oldPassword,
    this.password,
    this.publicKeyAlgorithm,
    this.publicKey,
    this.signature,
    this.languageTag,
    this.submethods,
    this.hostKeyAlgorithm,
    this.hostKey,
    this.hostName,
    this.userNameOnClientHost,
    this.gssapiMechanismOids,
    this.gssapiToken,
    this.gssapiMic,
  });

  /// Creates a password authentication request.
  ///
  /// The [password] will be encoded as UTF-8 as required by RFC 4252.
  /// The client should ensure the password is properly normalized before
  /// calling this constructor.
  factory SSH_Message_Userauth_Request.password({
    required String user,
    required String password,
    String serviceName = 'ssh-connection',
  }) {
    // RFC 4252: Password must be in UTF-8 encoding
    // Validate that the password can be properly encoded as UTF-8
    try {
      utf8.encode(password);
    } catch (e) {
      throw ArgumentError('Password must be valid UTF-8: $e');
    }

    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: user,
      password: password,
      methodName: 'password',
    );
  }

  /// Creates a password change request.
  ///
  /// Both [oldPassword] and [newPassword] will be encoded as UTF-8
  /// as required by RFC 4252.
  factory SSH_Message_Userauth_Request.newPassword({
    required String user,
    required String oldPassword,
    required String newPassword,
    String serviceName = 'ssh-connection',
  }) {
    // RFC 4252: Both passwords must be in UTF-8 encoding
    try {
      utf8.encode(oldPassword);
      utf8.encode(newPassword);
    } catch (e) {
      throw ArgumentError('Passwords must be valid UTF-8: $e');
    }

    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: user,
      oldPassword: oldPassword,
      password: newPassword,
      methodName: 'password',
    );
  }

  factory SSH_Message_Userauth_Request.publicKey({
    required String username,
    required String publicKeyAlgorithm,
    required Uint8List publicKey,
    required Uint8List? signature,
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: username,
      publicKeyAlgorithm: publicKeyAlgorithm,
      publicKey: publicKey,
      signature: signature,
      methodName: 'publickey',
    );
  }

  factory SSH_Message_Userauth_Request.keyboardInteractive({
    required String user,
    String languageTag = '',
    String submethods = '',
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: user,
      languageTag: languageTag,
      submethods: submethods,
      methodName: 'keyboard-interactive',
    );
  }

  factory SSH_Message_Userauth_Request.hostbased({
    required String username,
    required String publicKeyAlgorithm,
    required Uint8List publicKey,
    required String hostName,
    required String userNameOnClientHost,
    required Uint8List signature,
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: username,
      methodName: 'hostbased',
      hostKeyAlgorithm: publicKeyAlgorithm,
      hostKey: publicKey,
      hostName: hostName,
      userNameOnClientHost: userNameOnClientHost,
      signature: signature,
    );
  }

  factory SSH_Message_Userauth_Request.none({
    required String user,
    String serviceName = 'ssh-connection',
  }) {
    return SSH_Message_Userauth_Request(
      serviceName: serviceName,
      user: user,
      methodName: 'none',
    );
  }

  factory SSH_Message_Userauth_Request.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final user = reader.readUtf8();
    final serviceName = reader.readUtf8();
    final methodName = reader.readUtf8();
    switch (methodName) {
      case 'password':
        final hasNewPassword = reader.readBool();
        final password = reader.readUtf8();
        if (hasNewPassword) {
          final newPassword = reader.readUtf8();
          return SSH_Message_Userauth_Request.newPassword(
            user: user,
            oldPassword: password,
            newPassword: newPassword,
            serviceName: serviceName,
          );
        } else {
          return SSH_Message_Userauth_Request.password(
            user: user,
            password: password,
            serviceName: serviceName,
          );
        }
      case 'publickey':
        final hasSignature = reader.readBool();
        final publicKeyAlgorithm = reader.readUtf8();
        final publicKey = reader.readString();
        Uint8List? signature;
        if (hasSignature) {
          signature = reader.readString();
        }
        return SSH_Message_Userauth_Request.publicKey(
          username: user,
          serviceName: serviceName,
          publicKeyAlgorithm: publicKeyAlgorithm,
          publicKey: publicKey,
          signature: signature,
        );
      case 'keyboard-interactive':
        final languageTag = reader.readUtf8();
        final submethods = reader.readUtf8();
        return SSH_Message_Userauth_Request.keyboardInteractive(
          user: user,
          serviceName: serviceName,
          languageTag: languageTag,
          submethods: submethods,
        );
      case 'hostbased':
        final hostKeyAlgorithm = reader.readUtf8();
        final hostKey = reader.readString();
        final hostName = reader.readUtf8();
        final userNameOnClientHost = reader.readUtf8();
        final signature = reader.readString();
        return SSH_Message_Userauth_Request(
          user: user,
          serviceName: serviceName,
          methodName: methodName,
          hostKeyAlgorithm: hostKeyAlgorithm,
          hostKey: hostKey,
          hostName: hostName,
          userNameOnClientHost: userNameOnClientHost,
          signature: signature,
        );
      case 'gssapi-with-mic':
        final oidCount = reader.readUint32();
        final mechanismOids = <String>[];
        for (var i = 0; i < oidCount; i++) {
          mechanismOids.add(reader.readUtf8());
        }
        // Read optional token
        Uint8List? token;
        Uint8List? mic;
        if (reader.available > 0) {
          token = reader.readString();
        }
        if (reader.available > 0) {
          mic = reader.readString();
        }
        return SSH_Message_Userauth_Request(
          user: user,
          serviceName: serviceName,
          methodName: methodName,
          gssapiMechanismOids: mechanismOids,
          gssapiToken: token,
          gssapiMic: mic,
        );
      case 'none':
        return SSH_Message_Userauth_Request.none(
          user: user,
          serviceName: serviceName,
        );
      default:
        throw UnimplementedError('Unrecognized method name: $methodName');
    }
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(user);
    writer.writeUtf8(serviceName);
    writer.writeUtf8(methodName);
    switch (methodName) {
      case 'password':
        if (oldPassword != null) {
          writer.writeBool(true);
          // RFC 4252: Ensure UTF-8 encoding for password transmission
          writer.writeUtf8(oldPassword!);
          writer.writeUtf8(password!);
        } else {
          writer.writeBool(false);
          // RFC 4252: Ensure UTF-8 encoding for password transmission
          writer.writeUtf8(password!);
        }
        break;
      case 'publickey':
        writer.writeBool(signature != null);
        writer.writeUtf8(publicKeyAlgorithm!);
        writer.writeString(publicKey!);
        if (signature != null) writer.writeString(signature!);
        break;
      case 'keyboard-interactive':
        writer.writeUtf8(languageTag!);
        writer.writeUtf8(submethods!);
        break;
      case 'hostbased':
        writer.writeUtf8(hostKeyAlgorithm!);
        writer.writeString(hostKey!);
        writer.writeUtf8(hostName!);
        writer.writeUtf8(userNameOnClientHost!);
        writer.writeString(signature!);
        break;
      case 'gssapi-with-mic':
        // RFC 4462 Section 3.1: GSSAPI mechanism OIDs
        writer.writeUint32(gssapiMechanismOids!.length);
        for (var oid in gssapiMechanismOids!) {
          writer.writeUtf8(oid);
        }
        // GSSAPI token for initial request
        if (gssapiToken != null) {
          writer.writeString(gssapiToken!);
        }
        // GSSAPI MIC for authentication
        if (gssapiMic != null) {
          writer.writeString(gssapiMic!);
        }
        break;
      case 'none':
        break;
      default:
        throw UnimplementedError('Unrecognized method name: $methodName');
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Request(user: $user, serviceName: $serviceName, methodName: $methodName)';
  }
}

class SSH_Message_Userauth_Failure extends SSHMessage {
  /// 51
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_FAILURE;

  final List<String> methodsLeft;
  final bool partialSuccess;

  SSH_Message_Userauth_Failure({
    required this.methodsLeft,
    this.partialSuccess = false,
  });

  factory SSH_Message_Userauth_Failure.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final methodsLeft = reader.readNameList();
    final partialSuccess = reader.readBool();
    return SSH_Message_Userauth_Failure(
      methodsLeft: methodsLeft,
      partialSuccess: partialSuccess,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeNameList(methodsLeft);
    writer.writeBool(partialSuccess);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Failure(methodsLeft: $methodsLeft, partialSuccess: $partialSuccess)';
  }
}

class SSH_Message_Userauth_Success extends SSHMessage {
  /// 52
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_SUCCESS;

  SSH_Message_Userauth_Success();

  factory SSH_Message_Userauth_Success.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    return SSH_Message_Userauth_Success();
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Success()';
  }
}

class SSH_Message_Userauth_Banner extends SSHMessage {
  /// 53
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_BANNER;

  final String message;
  final String language;

  SSH_Message_Userauth_Banner({
    required this.message,
    this.language = '',
  });

  factory SSH_Message_Userauth_Banner.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final message = reader.readUtf8();
    final language = reader.readUtf8();
    return SSH_Message_Userauth_Banner(
      message: message,
      language: language,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(message);
    writer.writeUtf8(language);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Banner(message: $message, language: $language)';
  }
}

class SSH_Message_Userauth_Passwd_ChangeReq extends SSHMessage {
  /// 60
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ;

  final String prompt;

  SSH_Message_Userauth_Passwd_ChangeReq({
    required this.prompt,
  });

  factory SSH_Message_Userauth_Passwd_ChangeReq.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final prompt = reader.readUtf8();
    return SSH_Message_Userauth_Passwd_ChangeReq(
      prompt: prompt,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(prompt);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_Userauth_Password_Change_Request(prompt: $prompt)';
  }
}

class SSH_Message_Userauth_InfoRequest implements SSHMessage {
  /// 60
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_INFO_REQUEST;

  final String name;
  final String instruction;
  final String lang;
  final List<SSHUserInfoPrompt> prompts;

  SSH_Message_Userauth_InfoRequest({
    required this.name,
    required this.instruction,
    required this.lang,
    required this.prompts,
  });

  factory SSH_Message_Userauth_InfoRequest.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final name = reader.readUtf8();
    final instruction = reader.readUtf8();
    final lang = reader.readUtf8();

    final prompts = <SSHUserInfoPrompt>[];
    final promptCount = reader.readUint32();
    for (var i = 0; i < promptCount; i++) {
      final prompt = reader.readUtf8();
      final echo = reader.readBool();
      prompts.add(SSHUserInfoPrompt(prompt, echo));
    }

    return SSH_Message_Userauth_InfoRequest(
      name: name,
      instruction: instruction,
      lang: lang,
      prompts: prompts,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUtf8(name);
    writer.writeUtf8(instruction);
    writer.writeUtf8(lang);
    writer.writeUint32(prompts.length);
    for (var prompt in prompts) {
      writer.writeUtf8(prompt.promptText);
      writer.writeBool(prompt.echo);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return '$runtimeType(name: $name, instruction: $instruction, lang: $lang, prompts: $prompts)';
  }
}

class SSH_Message_Userauth_InfoResponse implements SSHMessage {
  /// 61
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_INFO_RESPONSE;

  final List<String> responses;

  SSH_Message_Userauth_InfoResponse({
    required this.responses,
  });

  factory SSH_Message_Userauth_InfoResponse.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final responseCount = reader.readUint32();
    final responses = <String>[];
    for (var i = 0; i < responseCount; i++) {
      responses.add(reader.readUtf8());
    }
    return SSH_Message_Userauth_InfoResponse(
      responses: responses,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(responses.length);
    for (var response in responses) {
      writer.writeUtf8(response);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return '$runtimeType(responses: $responses)';
  }
}

/// GSSAPI response message (RFC 4462 Section 3.2)
class SSH_Message_Userauth_GSSAPI_Response implements SSHMessage {
  /// 60
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_GSSAPI_RESPONSE;

  final List<String> mechanismOids;

  SSH_Message_Userauth_GSSAPI_Response({
    required this.mechanismOids,
  });

  factory SSH_Message_Userauth_GSSAPI_Response.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final oidCount = reader.readUint32();
    final mechanismOids = <String>[];
    for (var i = 0; i < oidCount; i++) {
      mechanismOids.add(reader.readUtf8());
    }
    return SSH_Message_Userauth_GSSAPI_Response(
      mechanismOids: mechanismOids,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(mechanismOids.length);
    for (var oid in mechanismOids) {
      writer.writeUtf8(oid);
    }
    return writer.takeBytes();
  }

  @override
  String toString() {
    return "$runtimeType(mechanismOids: $mechanismOids)";
  }
}

/// GSSAPI token message (RFC 4462 Section 3.3)
class SSH_Message_Userauth_GSSAPI_Token implements SSHMessage {
  /// 61
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_GSSAPI_TOKEN;

  final Uint8List token;

  SSH_Message_Userauth_GSSAPI_Token({
    required this.token,
  });

  factory SSH_Message_Userauth_GSSAPI_Token.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final token = reader.readString();
    return SSH_Message_Userauth_GSSAPI_Token(
      token: token,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeString(token);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return "$runtimeType(token length: ${token.length})";
  }
}

/// GSSAPI exchange complete message (RFC 4462 Section 3.4)
class SSH_Message_Userauth_GSSAPI_ExchangeComplete implements SSHMessage {
  /// 63
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE;

  SSH_Message_Userauth_GSSAPI_ExchangeComplete();

  factory SSH_Message_Userauth_GSSAPI_ExchangeComplete.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    return SSH_Message_Userauth_GSSAPI_ExchangeComplete();
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return "$runtimeType()";
  }
}

/// GSSAPI error message (RFC 4462 Section 3.5)
class SSH_Message_Userauth_GSSAPI_Error implements SSHMessage {
  /// 64
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_GSSAPI_ERROR;

  final Uint32List majorStatus;
  final Uint32List minorStatus;
  final String message;
  final String? languageTag;

  SSH_Message_Userauth_GSSAPI_Error({
    required this.majorStatus,
    required this.minorStatus,
    required this.message,
    this.languageTag,
  });

  factory SSH_Message_Userauth_GSSAPI_Error.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final majorStatus = reader.readUint32();
    final minorStatus = reader.readUint32();
    final message = reader.readUtf8();
    final languageTag = reader.readString();
    return SSH_Message_Userauth_GSSAPI_Error(
      majorStatus: Uint32List.fromList([majorStatus]),
      minorStatus: Uint32List.fromList([minorStatus]),
      message: message,
      languageTag: languageTag.isEmpty ? null : languageTag,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(majorStatus[0]);
    writer.writeUint32(minorStatus[0]);
    writer.writeUtf8(message);
    writer.writeUtf8(languageTag ?? '');
    return writer.takeBytes();
  }

  @override
  String toString() {
    return "$runtimeType(major: $majorStatus, minor: $minorStatus, message: $message)";
  }
}

/// GSSAPI error token message (RFC 4462 Section 3.6)
class SSH_Message_Userauth_GSSAPI_ErrTok implements SSHMessage {
  /// 65
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_GSSAPI_ERRTOK;

  final Uint8List errorToken;

  SSH_Message_Userauth_GSSAPI_ErrTok({
    required this.errorToken,
  });

  factory SSH_Message_Userauth_GSSAPI_ErrTok.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final errorToken = reader.readString();
    return SSH_Message_Userauth_GSSAPI_ErrTok(
      errorToken: errorToken,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeString(errorToken);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return "$runtimeType(errorToken length: ${errorToken.length})";
  }
}

/// GSSAPI MIC message (RFC 4462 Section 3.7)
class SSH_Message_Userauth_GSSAPI_MIC implements SSHMessage {
  /// 66
  static const messageId = SSHUserAuthMessageNumbers.SSH_MSG_USERAUTH_GSSAPI_MIC;

  final Uint8List mic;

  SSH_Message_Userauth_GSSAPI_MIC({
    required this.mic,
  });

  factory SSH_Message_Userauth_GSSAPI_MIC.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final mic = reader.readString();
    return SSH_Message_Userauth_GSSAPI_MIC(
      mic: mic,
    );
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeString(mic);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return "$runtimeType(mic length: ${mic.length})";
  }
}

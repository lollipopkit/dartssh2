import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

/// The decision `_updateAuthMethodsBasedOnServerResponse` makes after every
/// `SSH_MSG_USERAUTH_FAILURE`: of the methods the server says can continue,
/// which ones can this client actually perform right now.
///
/// Every case below turns on the difference between "was configured" and "is
/// left", which is what the client used to get wrong.
void main() {
  List<SSHAuthMethod> resolve(
    List<String> serverMethods, {
    bool hasUntriedKeys = false,
    bool hasUntriedHostbasedKeys = false,
    bool canSupplyPassword = false,
    bool canAnswerUserInfo = false,
    bool hasHostbasedIdentity = false,
    void Function(String)? onNote,
  }) {
    return continuableAuthMethods(
      serverMethods: serverMethods,
      hasUntriedKeys: hasUntriedKeys,
      hasUntriedHostbasedKeys: hasUntriedHostbasedKeys,
      canSupplyPassword: canSupplyPassword,
      canAnswerUserInfo: canAnswerUserInfo,
      hasHostbasedIdentity: hasHostbasedIdentity,
      onNote: onNote,
    );
  }

  group('publickey', () {
    test('is offered while a key is left', () {
      expect(
        resolve(['publickey'], hasUntriedKeys: true),
        [SSHAuthMethod.publicKey],
      );
    });

    test('is dropped once every key has been offered', () {
      expect(
        resolve(['publickey'], hasUntriedKeys: false),
        isEmpty,
        reason: 'the server lists what it accepts, not what is left to try',
      );
    });

    test('does not crowd out password once the keys are gone', () {
      expect(
        resolve(
          ['publickey', 'password'],
          hasUntriedKeys: false,
          canSupplyPassword: true,
        ),
        [SSHAuthMethod.password],
        reason: 'this is the combination that used to end in a crash: a key '
            'the server rejected, a password never reached',
      );
    });

    test('comes before password while a key is left, as the server asked', () {
      expect(
        resolve(
          ['publickey', 'password'],
          hasUntriedKeys: true,
          canSupplyPassword: true,
        ),
        [SSHAuthMethod.publicKey, SSHAuthMethod.password],
      );
    });
  });

  group('hostbased', () {
    test('needs a key left, a host name and an account', () {
      expect(
        resolve(
          ['hostbased'],
          hasUntriedHostbasedKeys: true,
          hasHostbasedIdentity: true,
        ),
        [SSHAuthMethod.hostbased],
      );
      expect(
        resolve(['hostbased'], hasUntriedHostbasedKeys: true),
        isEmpty,
        reason: 'without a host name there is nothing to sign for',
      );
      expect(
        resolve(['hostbased'], hasHostbasedIdentity: true),
        isEmpty,
        reason: 'the same mistake publickey had, in the other branch',
      );
    });
  });

  group('the rest', () {
    test('password is offered only with somewhere to get one from', () {
      expect(resolve(['password'], canSupplyPassword: true),
          [SSHAuthMethod.password]);
      expect(resolve(['password']), isEmpty);
    });

    test('keyboard-interactive is offered only with somewhere to answer', () {
      expect(resolve(['keyboard-interactive'], canAnswerUserInfo: true),
          [SSHAuthMethod.keyboardInteractive]);
      expect(resolve(['keyboard-interactive']), isEmpty);
    });

    test('an empty list from the server leaves nothing to try', () {
      expect(
        resolve([], hasUntriedKeys: true, canSupplyPassword: true),
        isEmpty,
      );
    });

    test('order follows the server, not this list', () {
      expect(
        resolve(
          ['password', 'keyboard-interactive', 'publickey'],
          hasUntriedKeys: true,
          canSupplyPassword: true,
          canAnswerUserInfo: true,
        ),
        [
          SSHAuthMethod.password,
          SSHAuthMethod.keyboardInteractive,
          SSHAuthMethod.publicKey,
        ],
      );
    });

    test('a repeated method is queued as often as the server names it', () {
      expect(
        resolve(['publickey', 'publickey'], hasUntriedKeys: true),
        [SSHAuthMethod.publicKey, SSHAuthMethod.publicKey],
        reason: 'each entry is one more attempt, and there is a key for it',
      );
    });
  });

  group('what the server said that could not be used', () {
    test('"none" is reported and never queued', () {
      final notes = <String>[];
      expect(resolve(['none'], onNote: notes.add), isEmpty);
      expect(notes, hasLength(1));
      expect(notes.single, contains('none'));
    });

    test('an unrecognised name is reported and never queued', () {
      final notes = <String>[];
      expect(resolve(['gssapi-with-mic'], onNote: notes.add), isEmpty);
      expect(notes.single, contains('gssapi-with-mic'));
    });

    test('a method that cannot be performed is passed over quietly', () {
      final notes = <String>[];
      expect(resolve(['publickey'], onNote: notes.add), isEmpty);
      expect(
        notes,
        isEmpty,
        reason: 'the server named something it accepts; there is nothing '
            'unexpected about it, only nothing left to answer with',
      );
    });
  });
}

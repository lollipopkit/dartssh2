import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_client.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

const _legacyAlgorithms = SSHAlgorithms(
  pubkey: [
    SSHPubkeyType.ed25519Cert,
    SSHPubkeyType.ed25519,
    SSHPubkeyType.skEd25519Cert,
    SSHPubkeyType.skEd25519,
    SSHPubkeyType.ecdsa521Cert,
    SSHPubkeyType.ecdsa521,
    SSHPubkeyType.ecdsa384Cert,
    SSHPubkeyType.ecdsa384,
    SSHPubkeyType.ecdsa256Cert,
    SSHPubkeyType.ecdsa256,
    SSHPubkeyType.skEcdsa256Cert,
    SSHPubkeyType.skEcdsa256,
    SSHPubkeyType.rsaSha256Cert,
    SSHPubkeyType.rsaSha256,
    SSHPubkeyType.rsaSha1Cert,
    SSHPubkeyType.rsaSha1,
  ],
);

void main() {
  final rsaPem =
      SSHKeyPair.fromPem(fixture('ssh-rsa/id_rsa', normalizeNewlines: true))
          .single as RsaPrivateKey;
  final rsaOther = SSHKeyPair.fromPem(
    fixture('ssh-rsa/ssh_host_rsa_key', normalizeNewlines: true),
  ).single as SSHRsaKeyPair;
  final rsaOpenSsh = SSHKeyPair.fromPem(
    fixture('ssh-rsa/id_rsa.openssh', normalizeNewlines: true),
  ).single as OpenSSHRsaKeyPair;
  final ed25519 = SSHKeyPair.fromPem(
    fixture('ssh-ed25519/id_ed25519', normalizeNewlines: true),
  ).single;
  final ecdsa256 = SSHKeyPair.fromPem(
    fixture('ecdsa-sha2-nistp256/id_ecdsa', normalizeNewlines: true),
  ).single;

  group('SSHRsaKeyPair.signWith & signerFor', () {
    for (final entry in {
      'RsaPrivateKey': rsaPem,
      'OpenSSHRsaKeyPair': rsaOpenSsh,
    }.entries) {
      test('${entry.key} signs and verifies under sha1, sha256, and sha512',
          () async {
        final key = entry.value;
        final pub = key.toPublicKey() as SSHRsaPublicKey;
        final data = Uint8List.fromList(utf8.encode('legacy-rsa-test-payload'));

        for (final algo in const [
          SSHRsaSignatureType.sha1,
          SSHRsaSignatureType.sha256,
          SSHRsaSignatureType.sha512,
        ]) {
          final signer = key.signerFor(algo);
          expect(signer, isNotNull);
          expect(signer!.type, algo);

          final encoded = await signer.sign(data);
          final decoded = SSHRsaSignature.decode(encoded);
          expect(decoded.type, algo);
          expect(pub.verify(data, decoded), isTrue);
        }

        expect(key.signerFor('ssh-ed25519'), isNull);
      });
    }

    test('non-RSA keys only return signer for their own type', () {
      expect(ed25519.signerFor('ssh-ed25519'), isNotNull);
      expect(ed25519.signerFor('ssh-rsa'), isNull);
      expect(ed25519.signerFor('rsa-sha2-256'), isNull);

      expect(ecdsa256.signerFor('ecdsa-sha2-nistp256'), isNotNull);
      expect(ecdsa256.signerFor('ecdsa-sha2-nistp384'), isNull);
      expect(ecdsa256.signerFor('ssh-rsa'), isNull);
    });
  });

  group('SSHAgentIdentity.signerFor', () {
    test('signs RSA agent key under rsa-sha2-256, rsa-sha2-512, and ssh-rsa',
        () async {
      final agent = _agentClient(SSHKeyPairAgent([rsaPem]));
      addTearDown(agent.close);
      final identity = (await agent.identities()).single;
      final pub = SSHRsaPublicKey.decode(identity.publicKey);
      final data = Uint8List.fromList([9, 8, 7, 6]);

      for (final algo in const [
        SSHRsaSignatureType.sha256,
        SSHRsaSignatureType.sha512,
        SSHRsaSignatureType.sha1,
      ]) {
        final signer = identity.signerFor(algo);
        expect(signer, isNotNull);
        expect(signer!.type, algo);

        final sig = SSHRsaSignature.decode(await signer.sign(data));
        expect(sig.type, algo);
        expect(pub.verify(data, sig), isTrue);
      }

      expect(identity.signerFor('ssh-rsa-cert-v01@openssh.com'), isNull);
      expect(identity.signerFor('ssh-ed25519'), isNull);
    });

    test('signs RSA cert agent key with cert algorithms and underlying flags',
        () async {
      final certBlob = _syntheticKeyBlob('ssh-rsa-cert-v01@openssh.com');
      final recordedFlags = <int>[];
      final agent = _agentClient(
        _SyntheticAgent(
          identities: [(blob: certBlob, comment: 'rsa-cert')],
          onSign: (blob, data, flags) {
            recordedFlags.add(flags);
            final innerType = flags == SSHAgentProtocol.rsaSha2_512
                ? SSHRsaSignatureType.sha512
                : flags == SSHAgentProtocol.rsaSha2_256
                    ? SSHRsaSignatureType.sha256
                    : SSHRsaSignatureType.sha1;
            return rsaPem.signWith(data, innerType).encode();
          },
        ),
      );
      addTearDown(agent.close);

      final identity = (await agent.identities()).single;
      final pub = rsaPem.toPublicKey() as SSHRsaPublicKey;
      final data = Uint8List.fromList([1, 3, 5, 7]);

      for (final pair in const [
        ('rsa-sha2-256-cert-v01@openssh.com', SSHRsaSignatureType.sha256),
        ('rsa-sha2-512-cert-v01@openssh.com', SSHRsaSignatureType.sha512),
        ('ssh-rsa-cert-v01@openssh.com', SSHRsaSignatureType.sha1),
      ]) {
        final signer = identity.signerFor(pair.$1);
        expect(signer, isNotNull);
        expect(signer!.type, pair.$1);

        final sig = SSHRsaSignature.decode(await signer.sign(data));
        expect(sig.type, pair.$2);
        expect(pub.verify(data, sig), isTrue);
      }

      expect(
        recordedFlags,
        [SSHAgentProtocol.rsaSha2_256, SSHAgentProtocol.rsaSha2_512, 0],
      );
      expect(identity.signerFor('ssh-rsa'), isNull);
      expect(identity.signerFor('rsa-sha2-256'), isNull);
    });

    test('rejects mismatched RSA signature type returned by agent', () async {
      final rsaBlob = rsaPem.toPublicKey().encode();
      final agent = _agentClient(
        _SyntheticAgent(
          identities: [(blob: rsaBlob, comment: 'bad-agent')],
          onSign: (blob, data, flags) {
            // Return the opposite signature type from what was requested.
            final wrongType = flags == 0
                ? SSHRsaSignatureType.sha256
                : SSHRsaSignatureType.sha1;
            return rsaPem.signWith(data, wrongType).encode();
          },
        ),
      );
      addTearDown(agent.close);

      final identity = (await agent.identities()).single;
      final data = Uint8List.fromList([2, 4, 6]);

      await expectLater(
        identity.signerFor('ssh-rsa')!.sign(data),
        throwsA(isA<SSHAgentError>()),
      );
      await expectLater(
        identity.signerFor('rsa-sha2-512')!.sign(data),
        throwsA(isA<SSHAgentError>()),
      );
    });
  });

  group('SSHClient publickey algorithm negotiation', () {
    test('falls back to SHA-1 ssh-rsa on legacy-only server when opted in',
        () async {
      for (final key in <SSHKeyPair>[rsaPem, rsaOpenSsh]) {
        final harness = _AuthHarness(
          identities: [key],
          algorithms: _legacyAlgorithms,
          acceptedPublicKeyAlgorithms: const {'ssh-rsa'},
          authorizedPublicKeys: [key.toPublicKey().encode()],
        );

        await harness.run();
        expect(harness.probedAlgorithms, ['rsa-sha2-256', 'ssh-rsa']);
        expect(harness.signedAlgorithms, ['ssh-rsa']);
        harness.close();
      }
    });

    test('does not offer SHA-1 ssh-rsa with default SSHAlgorithms', () async {
      final harness = _AuthHarness(
        identities: [rsaPem],
        algorithms: const SSHAlgorithms(),
        acceptedPublicKeyAlgorithms: const {'ssh-rsa'},
        authorizedPublicKeys: [rsaPem.toPublicKey().encode()],
      );

      await expectLater(harness.run(), throwsA(isA<SSHAuthFailError>()));
      expect(harness.probedAlgorithms, ['rsa-sha2-256']);
      expect(harness.signedAlgorithms, isEmpty);
      harness.close();
    });

    test('prefers rsa-sha2-256 on modern server even when legacy is enabled',
        () async {
      final harness = _AuthHarness(
        identities: [rsaOpenSsh],
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {'rsa-sha2-256', 'ssh-rsa'},
        authorizedPublicKeys: [rsaOpenSsh.toPublicKey().encode()],
      );

      await harness.run();
      expect(harness.probedAlgorithms, ['rsa-sha2-256']);
      expect(harness.signedAlgorithms, ['rsa-sha2-256']);
      harness.close();
    });

    test('negotiates rsa-sha2-512 when configured in algorithms.pubkey',
        () async {
      final harness = _AuthHarness(
        identities: [rsaOpenSsh],
        algorithms: const SSHAlgorithms(
          pubkey: [SSHPubkeyType.rsaSha256, SSHPubkeyType.rsaSha512],
        ),
        acceptedPublicKeyAlgorithms: const {'rsa-sha2-512'},
        authorizedPublicKeys: [rsaOpenSsh.toPublicKey().encode()],
      );

      await harness.run();
      expect(harness.probedAlgorithms, ['rsa-sha2-256', 'rsa-sha2-512']);
      expect(harness.signedAlgorithms, ['rsa-sha2-512']);
      harness.close();
    });

    test('tries all modern keys (identities + agent) before any SHA-1 fallback',
        () async {
      final agent = _agentClient(SSHKeyPairAgent([ed25519]));
      addTearDown(agent.close);

      final harness = _AuthHarness(
        identities: [rsaPem],
        identityAgent: agent,
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {'ssh-ed25519', 'ssh-rsa'},
        authorizedPublicKeys: [ed25519.toPublicKey().encode()],
      );

      await harness.run();
      expect(harness.probedAlgorithms, ['rsa-sha2-256', 'ssh-ed25519']);
      expect(harness.signedAlgorithms, ['ssh-ed25519']);
      harness.close();
    });

    test(
        'still tries rsa-sha2-256 before ssh-rsa even if pubkey lists sha1 first',
        () async {
      final harness = _AuthHarness(
        identities: [rsaPem],
        algorithms: const SSHAlgorithms(
          pubkey: [
            SSHPubkeyType.rsaSha1,
            SSHPubkeyType.rsaSha256,
            SSHPubkeyType.rsaSha256,
            SSHPubkeyType.rsaSha1,
          ],
        ),
        acceptedPublicKeyAlgorithms: const {'ssh-rsa'},
        authorizedPublicKeys: [rsaPem.toPublicKey().encode()],
      );

      await harness.run();
      expect(harness.probedAlgorithms, ['rsa-sha2-256', 'ssh-rsa']);
      expect(harness.signedAlgorithms, ['ssh-rsa']);
      harness.close();
    });

    test('falls back to SHA-1 ssh-rsa for SSH agent RSA keys when opted in',
        () async {
      final agent = _agentClient(SSHKeyPairAgent([rsaPem]));
      addTearDown(agent.close);

      final harness = _AuthHarness(
        identityAgent: agent,
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {'ssh-rsa'},
        authorizedPublicKeys: [rsaPem.toPublicKey().encode()],
      );

      await harness.run();
      expect(harness.probedAlgorithms, ['rsa-sha2-256', 'ssh-rsa']);
      expect(harness.signedAlgorithms, ['ssh-rsa']);
      harness.close();
    });

    test(
        'falls back to SHA-1 ssh-rsa-cert for SSH agent RSA cert when opted in',
        () async {
      final certBlob = _syntheticKeyBlob('ssh-rsa-cert-v01@openssh.com');
      final agent = _agentClient(
        _SyntheticAgent(
          identities: [(blob: certBlob, comment: 'rsa-cert')],
          onSign: (blob, data, flags) {
            final innerType = flags == SSHAgentProtocol.rsaSha2_256
                ? SSHRsaSignatureType.sha256
                : SSHRsaSignatureType.sha1;
            return rsaPem.signWith(data, innerType).encode();
          },
        ),
      );
      addTearDown(agent.close);

      final harness = _AuthHarness(
        identityAgent: agent,
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {'ssh-rsa-cert-v01@openssh.com'},
        authorizedPublicKeys: [certBlob],
        customVerifier: (algo, pubBlob, challenge, sigBlob) {
          final sig = SSHRsaSignature.decode(sigBlob);
          return algo == 'ssh-rsa-cert-v01@openssh.com' &&
              sig.type == SSHRsaSignatureType.sha1 &&
              (rsaPem.toPublicKey() as SSHRsaPublicKey).verify(challenge, sig);
        },
      );

      await harness.run();
      expect(
        harness.probedAlgorithms,
        ['rsa-sha2-256-cert-v01@openssh.com', 'ssh-rsa-cert-v01@openssh.com'],
      );
      expect(harness.signedAlgorithms, ['ssh-rsa-cert-v01@openssh.com']);
      harness.close();
    });

    test(
        'preserves FIDO2 sk-* security keys from agent under default algorithms',
        () async {
      for (final skType in const [
        'sk-ssh-ed25519@openssh.com',
        'sk-ecdsa-sha2-nistp256@openssh.com',
      ]) {
        final skBlob = _syntheticKeyBlob(skType);
        final sigPayload = (SSHMessageWriter()
              ..writeUtf8(skType)
              ..writeString(Uint8List.fromList([1, 2, 3, 4])))
            .takeBytes();
        final agent = _agentClient(
          _SyntheticAgent(
            identities: [(blob: skBlob, comment: skType)],
            onSign: (blob, data, flags) => sigPayload,
          ),
        );
        addTearDown(agent.close);

        final harness = _AuthHarness(
          identityAgent: agent,
          algorithms: const SSHAlgorithms(),
          acceptedPublicKeyAlgorithms: {skType},
          authorizedPublicKeys: [skBlob],
          customVerifier: (algo, pubBlob, challenge, sigBlob) =>
              algo == skType && _bytesEqual(sigBlob, sigPayload),
        );

        await harness.run();
        expect(harness.probedAlgorithms, [skType]);
        expect(harness.signedAlgorithms, [skType]);
        harness.close();
      }
    });

    test('enforces algorithms.pubkey and SHA-1 ordering on custom signers',
        () async {
      final sha1Signer = rsaPem.signerFor('ssh-rsa')!;

      // Blocked under default algorithms.
      final blocked = _AuthHarness(
        signers: [sha1Signer],
        algorithms: const SSHAlgorithms(),
        acceptedPublicKeyAlgorithms: const {'ssh-rsa'},
        authorizedPublicKeys: [rsaPem.toPublicKey().encode()],
      );
      await expectLater(blocked.run(), throwsA(isA<SSHAuthFailError>()));
      expect(blocked.probedAlgorithms, isEmpty);
      blocked.close();

      // Blocked when algorithms.pubkey is empty.
      final emptyPubkey = _AuthHarness(
        identities: [ed25519],
        signers: [ed25519.signer],
        algorithms: const SSHAlgorithms(pubkey: []),
        acceptedPublicKeyAlgorithms: const {'ssh-ed25519'},
        authorizedPublicKeys: [ed25519.toPublicKey().encode()],
      );
      await expectLater(emptyPubkey.run(), throwsA(isA<SSHAuthFailError>()));
      expect(emptyPubkey.probedAlgorithms, isEmpty);
      emptyPubkey.close();

      // Under legacy, SHA-1 signer passed first still yields to modern signers.
      final ordered = _AuthHarness(
        signers: [sha1Signer, ed25519.signer],
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {'ssh-ed25519', 'ssh-rsa'},
        authorizedPublicKeys: [ed25519.toPublicKey().encode()],
      );
      await ordered.run();
      expect(ordered.probedAlgorithms, ['ssh-ed25519']);
      expect(ordered.signedAlgorithms, ['ssh-ed25519']);
      ordered.close();
    });

    test(
        'moves to keyboard-interactive after partialSuccess instead of '
        'retrying legacy ssh-rsa fallback', () async {
      final harness = _AuthHarness(
        identities: [rsaPem],
        algorithms: _legacyAlgorithms,
        onUserInfoRequest: (_) => const ['123456'],
        acceptedPublicKeyAlgorithms: const {'rsa-sha2-256'},
        authorizedPublicKeys: [rsaPem.toPublicKey().encode()],
        partialSuccessNextMethods: const ['keyboard-interactive'],
      );

      await harness.run();
      expect(harness.probedAlgorithms, ['rsa-sha2-256']);
      expect(harness.signedAlgorithms, ['rsa-sha2-256']);
      expect(harness.keyboardInteractiveRequested, isTrue);
      harness.close();
    });

    test(
        'fails immediately after partialSuccess when no handler exists for '
        'remaining methods without probing ssh-rsa', () async {
      final harness = _AuthHarness(
        identities: [rsaPem],
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {'rsa-sha2-256'},
        authorizedPublicKeys: [rsaPem.toPublicKey().encode()],
        partialSuccessNextMethods: const ['keyboard-interactive'],
      );

      await expectLater(harness.run(), throwsA(isA<SSHAuthFailError>()));
      expect(harness.probedAlgorithms, ['rsa-sha2-256']);
      expect(harness.signedAlgorithms, ['rsa-sha2-256']);
      harness.close();
    });

    test('supports custom signer algorithm names via SSHPubkeyType.custom',
        () async {
      const customAlgo = 'custom-sig@example.com';
      final blob = _syntheticKeyBlob(customAlgo);
      final sig = Uint8List.fromList([0xca, 0xfe, 0xba, 0xbe]);
      final customSigner = _CallbackSigner(
        type: customAlgo,
        publicKey: blob,
        onSign: (_) async => sig,
      );

      // Rejected when not listed in algorithms.pubkey.
      final rejected = _AuthHarness(
        signers: [customSigner],
        algorithms: const SSHAlgorithms(),
        acceptedPublicKeyAlgorithms: const {customAlgo},
        authorizedPublicKeys: [blob],
        customVerifier: (algo, pub, challenge, s) =>
            algo == customAlgo && _bytesEqual(s, sig),
      );
      await expectLater(rejected.run(), throwsA(isA<SSHAuthFailError>()));
      expect(rejected.probedAlgorithms, isEmpty);
      rejected.close();

      // Accepted when explicitly opted in via SSHPubkeyType.custom.
      final accepted = _AuthHarness(
        signers: [customSigner],
        algorithms: const SSHAlgorithms(
          pubkey: [SSHPubkeyType.custom(customAlgo)],
        ),
        acceptedPublicKeyAlgorithms: const {customAlgo},
        authorizedPublicKeys: [blob],
        customVerifier: (algo, pub, challenge, s) =>
            algo == customAlgo && _bytesEqual(s, sig),
      );
      await accepted.run();
      expect(accepted.probedAlgorithms, [customAlgo]);
      expect(accepted.signedAlgorithms, [customAlgo]);
      accepted.close();
    });

    test(
        'drops remaining RSA fallbacks for already-authenticated key on '
        'partialSuccess publickey,publickey', () async {
      // rsa-sha2-256 and rsa-sha2-512 both precede ed25519 in `_signersLeft`,
      // and the server accepts both RSA algorithms — so without pruning,
      // rsa-sha2-512 would be probed before ed25519.
      final harness = _AuthHarness(
        identities: [rsaPem, ed25519],
        algorithms: const SSHAlgorithms(
          pubkey: [
            SSHPubkeyType.rsaSha256,
            SSHPubkeyType.rsaSha512,
            SSHPubkeyType.ed25519,
          ],
        ),
        acceptedPublicKeyAlgorithms: const {
          'rsa-sha2-256',
          'rsa-sha2-512',
          'ssh-ed25519',
        },
        authorizedPublicKeys: [
          rsaPem.toPublicKey().encode(),
          ed25519.toPublicKey().encode(),
        ],
        partialSuccessNextMethods: const ['publickey'],
      );

      await harness.run();
      expect(harness.probedAlgorithms, ['rsa-sha2-256', 'ssh-ed25519']);
      expect(harness.signedAlgorithms, ['rsa-sha2-256', 'ssh-ed25519']);
      harness.close();

      // With a single RSA key and legacy enabled, partialSuccess prunes its
      // ssh-rsa fallback instead of probing it again.
      final singleKey = _AuthHarness(
        identities: [rsaPem],
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {'rsa-sha2-256', 'ssh-rsa'},
        authorizedPublicKeys: [rsaPem.toPublicKey().encode()],
        partialSuccessNextMethods: const ['publickey'],
      );

      await expectLater(singleKey.run(), throwsA(isA<SSHAuthFailError>()));
      expect(singleKey.probedAlgorithms, ['rsa-sha2-256']);
      expect(singleKey.signedAlgorithms, ['rsa-sha2-256']);
      singleKey.close();
    });

    test(
        'prunes plain and cert RSA variants with matching (e, n) on '
        'partialSuccess while keeping distinct RSA keys', () async {
      final rsaPub = rsaPem.toPublicKey() as SSHRsaPublicKey;
      final otherPub = rsaOther.toPublicKey() as SSHRsaPublicKey;
      expect(otherPub.n, isNot(rsaPub.n));
      final certBlob = _syntheticRsaCertBlob(rsaPub.e, rsaPub.n);
      final otherBlob = otherPub.encode();

      final agent = _agentClient(
        _SyntheticAgent(
          identities: [
            (blob: certBlob, comment: 'rsa-cert'),
            (blob: rsaPub.encode(), comment: 'same-rsa-plain'),
            (blob: otherBlob, comment: 'distinct-rsa'),
          ],
          onSign: (blob, data, flags) {
            final key = _bytesEqual(blob, otherBlob) ? rsaOther : rsaPem;
            return key.signWith(data, SSHRsaSignatureType.sha256).encode();
          },
        ),
      );
      addTearDown(agent.close);

      final probedBlobs = <Uint8List>[];
      final harness = _AuthHarness(
        identityAgent: agent,
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {
          'rsa-sha2-256-cert-v01@openssh.com',
          'rsa-sha2-256',
          'ssh-rsa',
        },
        authorizedPublicKeys: [certBlob, rsaPub.encode(), otherBlob],
        partialSuccessNextMethods: const ['publickey'],
        onProbe: (algo, blob) => probedBlobs.add(Uint8List.fromList(blob)),
        customVerifier: (algo, pubBlob, challenge, sigBlob) {
          final sig = SSHRsaSignature.decode(sigBlob);
          final pub = _bytesEqual(pubBlob, otherBlob)
              ? rsaOther.toPublicKey() as SSHRsaPublicKey
              : rsaPub;
          return pub.verify(challenge, sig);
        },
      );

      await harness.run();
      expect(
        harness.probedAlgorithms,
        ['rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-256'],
      );
      // Second probe must be the distinct RSA key, not the plain variant of
      // the already-authenticated certificate key.
      expect(probedBlobs.length, 2);
      expect(_bytesEqual(probedBlobs[0], certBlob), isTrue);
      expect(_bytesEqual(probedBlobs[1], otherBlob), isTrue);
      harness.close();
    });

    test(
        'snapshots signer publicKey so in-place mutation during sign() cannot '
        'defeat partialSuccess pruning', () async {
      final originalBlob = rsaPem.toPublicKey().encode();
      final mutableBlob = Uint8List.fromList(originalBlob);
      final mutatingPrimary = _CallbackSigner(
        type: 'rsa-sha2-256',
        publicKey: mutableBlob,
        onSign: (challenge) async {
          final sig = rsaPem.signWith(challenge, 'rsa-sha2-256').encode();
          // Mutate the caller-owned buffer in place during signing.
          mutableBlob.fillRange(0, mutableBlob.length, 0);
          return sig;
        },
      );
      final fallbackSameKey = rsaPem.signerFor('rsa-sha2-512')!;

      final harness = _AuthHarness(
        signers: [mutatingPrimary, fallbackSameKey, ed25519.signer],
        algorithms: const SSHAlgorithms(
          pubkey: [
            SSHPubkeyType.rsaSha256,
            SSHPubkeyType.rsaSha512,
            SSHPubkeyType.ed25519,
          ],
        ),
        acceptedPublicKeyAlgorithms: const {
          'rsa-sha2-256',
          'rsa-sha2-512',
          'ssh-ed25519',
        },
        authorizedPublicKeys: [originalBlob, ed25519.toPublicKey().encode()],
        partialSuccessNextMethods: const ['publickey'],
      );

      await harness.run();
      expect(harness.probedAlgorithms, ['rsa-sha2-256', 'ssh-ed25519']);
      expect(harness.signedAlgorithms, ['rsa-sha2-256', 'ssh-ed25519']);
      harness.close();
    });

    test(
        'stops probing publickey when server drops publickey from methodsLeft '
        'even with no password handler', () async {
      final harness = _AuthHarness(
        identities: [rsaPem],
        algorithms: _legacyAlgorithms,
        acceptedPublicKeyAlgorithms: const {'ssh-rsa'},
        authorizedPublicKeys: [rsaPem.toPublicKey().encode()],
        failureMethodsAfterPublicKeyProbe: const ['password'],
      );

      await expectLater(harness.run(), throwsA(isA<SSHAuthFailError>()));
      expect(harness.probedAlgorithms, ['rsa-sha2-256']);
      expect(harness.signedAlgorithms, isEmpty);
      harness.close();
    });
  });
}

class _AuthHarness {
  _AuthHarness({
    List<SSHKeyPair>? identities,
    List<SSHSigner>? signers,
    SSHAgentClient? identityAgent,
    SSHAlgorithms algorithms = const SSHAlgorithms(),
    SSHUserInfoRequestHandler? onUserInfoRequest,
    required this.acceptedPublicKeyAlgorithms,
    required this.authorizedPublicKeys,
    this.partialSuccessNextMethods,
    this.failureMethodsAfterPublicKeyProbe = const ['publickey'],
    this.onProbe,
    this.customVerifier,
  }) {
    _socket = _LoopbackPacketSocket(_onClientPacket);
    client = SSHClient(
      _socket,
      username: 'root',
      identities: identities,
      signers: signers,
      identityAgent: identityAgent,
      algorithms: algorithms,
      onUserInfoRequest: onUserInfoRequest,
      keepAliveInterval: null,
    );
    client.transport
      ..sessionId = _sessionId
      ..kexInProgress = false;
  }

  static final _sessionId =
      Uint8List.fromList(List<int>.generate(32, (i) => i));

  final Set<String> acceptedPublicKeyAlgorithms;
  final List<Uint8List> authorizedPublicKeys;
  final List<String>? partialSuccessNextMethods;
  final List<String> failureMethodsAfterPublicKeyProbe;
  final void Function(String algorithm, Uint8List publicKey)? onProbe;
  final bool Function(
    String algorithm,
    Uint8List publicKey,
    Uint8List challenge,
    Uint8List signatureBlob,
  )? customVerifier;

  final probedAlgorithms = <String>[];
  final signedAlgorithms = <String>[];
  var keyboardInteractiveRequested = false;
  var _partialSucceededOnce = false;

  late final _LoopbackPacketSocket _socket;
  late final SSHClient client;

  Future<void> run() {
    client.handleTransportReady();
    return client.authenticated;
  }

  void close() => client.close();

  void _onClientPacket(Uint8List payload) {
    if (payload.isEmpty) return;
    switch (payload[0]) {
      case SSH_Message_Service_Request.messageId:
        final req = SSH_Message_Service_Request.decode(payload);
        client
            .handlePacket(SSH_Message_Service_Accept(req.serviceName).encode());
      case SSH_Message_Userauth_Request.messageId:
        _handleUserauth(payload);
    }
  }

  void _handleUserauth(Uint8List payload) {
    final reader = SSHMessageReader(payload);
    reader.skip(1);
    final username = reader.readUtf8();
    final service = reader.readUtf8();
    final method = reader.readUtf8();

    if (method == 'none') {
      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['publickey', 'keyboard-interactive'],
          partialSuccess: false,
        ).encode(),
      );
      return;
    }

    if (method == 'keyboard-interactive') {
      keyboardInteractiveRequested = true;
      client.handlePacket(SSH_Message_Userauth_Success().encode());
      return;
    }

    if (method != 'publickey') {
      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['publickey'],
          partialSuccess: false,
        ).encode(),
      );
      return;
    }

    final hasSignature = reader.readBool();
    final algorithm = reader.readUtf8();
    final publicKey = reader.readString();

    final keyAuthorized =
        authorizedPublicKeys.any((k) => _bytesEqual(k, publicKey));
    final algoAllowed = acceptedPublicKeyAlgorithms.contains(algorithm);

    if (!hasSignature) {
      probedAlgorithms.add(algorithm);
      onProbe?.call(algorithm, publicKey);
      if (keyAuthorized && algoAllowed) {
        client.handlePacket(
          SSH_Message_Userauth_Pk_Ok(
            publicKeyAlgorithm: algorithm,
            publicKey: publicKey,
          ).encode(),
        );
      } else {
        client.handlePacket(
          SSH_Message_Userauth_Failure(
            methodsLeft: failureMethodsAfterPublicKeyProbe,
            partialSuccess: false,
          ).encode(),
        );
      }
      return;
    }

    final signatureBlob = reader.readString();
    signedAlgorithms.add(algorithm);

    final challenge = (SSHMessageWriter()
          ..writeString(_sessionId)
          ..writeUint8(SSH_Message_Userauth_Request.messageId)
          ..writeUtf8(username)
          ..writeUtf8(service)
          ..writeUtf8('publickey')
          ..writeBool(true)
          ..writeUtf8(algorithm)
          ..writeString(publicKey))
        .takeBytes();

    final verified = customVerifier != null
        ? customVerifier!(algorithm, publicKey, challenge, signatureBlob)
        : _verifySignature(algorithm, publicKey, challenge, signatureBlob);
    if (keyAuthorized && algoAllowed && verified) {
      if (partialSuccessNextMethods != null && !_partialSucceededOnce) {
        _partialSucceededOnce = true;
        client.handlePacket(
          SSH_Message_Userauth_Failure(
            methodsLeft: partialSuccessNextMethods!,
            partialSuccess: true,
          ).encode(),
        );
      } else {
        client.handlePacket(SSH_Message_Userauth_Success().encode());
      }
    } else {
      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['publickey'],
          partialSuccess: false,
        ).encode(),
      );
    }
  }

  bool _verifySignature(
    String algorithm,
    Uint8List publicKey,
    Uint8List challenge,
    Uint8List signatureBlob,
  ) {
    if (algorithm == 'ssh-ed25519') {
      final pub = SSHEd25519PublicKey.decode(publicKey);
      final sig = SSHEd25519Signature.decode(signatureBlob);
      return pub.verify(challenge, sig);
    }
    final pub = SSHRsaPublicKey.decode(publicKey);
    final sig = SSHRsaSignature.decode(signatureBlob);
    return sig.type == algorithm && pub.verify(challenge, sig);
  }
}

Uint8List _syntheticKeyBlob(String keyType) {
  return (SSHMessageWriter()
        ..writeUtf8(keyType)
        ..writeString(Uint8List.fromList([0xde, 0xad, 0xbe, 0xef])))
      .takeBytes();
}

Uint8List _syntheticRsaCertBlob(BigInt e, BigInt n) {
  return (SSHMessageWriter()
        ..writeUtf8('ssh-rsa-cert-v01@openssh.com')
        ..writeString(Uint8List(32)) // nonce
        ..writeMpint(e)
        ..writeMpint(n))
      .takeBytes();
}

class _CallbackSigner implements SSHSigner {
  _CallbackSigner({
    required this.type,
    required this.publicKey,
    required this.onSign,
  });

  @override
  final String type;

  @override
  final Uint8List publicKey;

  final Future<Uint8List> Function(Uint8List data) onSign;

  @override
  Future<Uint8List> sign(Uint8List data) => onSign(data);
}

class _SyntheticAgent implements SSHAgentHandler {
  _SyntheticAgent({
    required this.identities,
    required this.onSign,
  });

  final List<({Uint8List blob, String comment})> identities;
  final Uint8List Function(Uint8List blob, Uint8List data, int flags) onSign;

  @override
  Future<Uint8List> handleRequest(Uint8List request) async {
    final reader = SSHMessageReader(request);
    switch (reader.readUint8()) {
      case SSHAgentProtocol.requestIdentities:
        final writer = SSHMessageWriter()
          ..writeUint8(SSHAgentProtocol.identitiesAnswer)
          ..writeUint32(identities.length);
        for (final id in identities) {
          writer
            ..writeString(id.blob)
            ..writeUtf8(id.comment);
        }
        return writer.takeBytes();
      case SSHAgentProtocol.signRequest:
        final blob = reader.readString();
        final data = reader.readString();
        final flags = reader.readUint32();
        final sig = onSign(blob, data, flags);
        return (SSHMessageWriter()
              ..writeUint8(SSHAgentProtocol.signResponse)
              ..writeString(sig))
            .takeBytes();
      default:
        return Uint8List.fromList([SSHAgentProtocol.failure]);
    }
  }
}

/// Captures cleartext binary SSH packets written by an unencrypted [SSHTransport]
/// after its version banner and delivers each payload to [onPacket].
class _LoopbackPacketSocket implements SSHSocket {
  _LoopbackPacketSocket(this._onPacket);

  final void Function(Uint8List payload) _onPacket;
  final _incoming = StreamController<Uint8List>();
  final _done = Completer<void>();
  late final _sink = _PacketParserSink(_onPacket);

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _sink;

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
    await _incoming.close();
  }

  @override
  void destroy() {
    if (!_done.isCompleted) _done.complete();
    unawaited(_incoming.close());
  }

  @override
  Future<void> flush() async {}
}

class _PacketParserSink implements StreamSink<List<int>> {
  _PacketParserSink(this._onPacket);

  final void Function(Uint8List payload) _onPacket;
  final _buffer = BytesBuilder();
  var _sawBanner = false;

  @override
  void add(List<int> data) {
    _buffer.add(data);
    var bytes = _buffer.takeBytes();

    if (!_sawBanner) {
      final crlf = _indexOfCrlf(bytes);
      if (crlf < 0) {
        _buffer.add(bytes);
        return;
      }
      _sawBanner = true;
      bytes = Uint8List.sublistView(bytes, crlf + 2);
    }

    while (bytes.length >= 5) {
      final packetLength = ByteData.sublistView(bytes, 0, 4).getUint32(0);
      if (bytes.length < 4 + packetLength) break;
      final paddingLength = bytes[4];
      final payloadLength = packetLength - paddingLength - 1;
      final payload = Uint8List.fromList(
        Uint8List.sublistView(bytes, 5, 5 + payloadLength),
      );
      bytes = Uint8List.sublistView(bytes, 4 + packetLength);
      scheduleMicrotask(() => _onPacket(payload));
    }

    if (bytes.isNotEmpty) {
      _buffer.add(bytes);
    }
  }

  int _indexOfCrlf(Uint8List bytes) {
    for (var i = 0; i + 1 < bytes.length; i++) {
      if (bytes[i] == 0x0d && bytes[i + 1] == 0x0a) return i;
    }
    return -1;
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}

SSHAgentClient _agentClient(SSHAgentHandler handler) {
  final toAgent = StreamController<List<int>>();
  final toClient = StreamController<Uint8List>();
  final buffer = BytesBuilder();
  toAgent.stream.listen((bytes) async {
    buffer.add(bytes);
    var all = buffer.takeBytes();
    while (all.length >= 4) {
      final len = ByteData.sublistView(all, 0, 4).getUint32(0);
      if (all.length < 4 + len) break;
      final frame = Uint8List.sublistView(all, 4, 4 + len);
      all = Uint8List.sublistView(all, 4 + len);
      final reply = await handler.handleRequest(frame);
      toClient.add(
        (BytesBuilder()
              ..add(
                (ByteData(4)..setUint32(0, reply.length)).buffer.asUint8List(),
              )
              ..add(reply))
            .takeBytes(),
      );
    }
    if (all.isNotEmpty) buffer.add(all);
  });
  return SSHAgentClient(_StreamPairSocket(toClient.stream, toAgent.sink));
}

class _StreamPairSocket implements SSHSocket {
  _StreamPairSocket(this.stream, this.sink);

  @override
  final Stream<Uint8List> stream;

  @override
  final StreamSink<List<int>> sink;

  @override
  Future<void> get done => sink.done;

  @override
  Future<void> close() async => sink.close();

  @override
  void destroy() => sink.close();

  @override
  Future<void> flush() async {}
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

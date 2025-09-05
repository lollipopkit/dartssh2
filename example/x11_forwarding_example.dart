import 'package:dartssh2/dartssh2.dart';

/// Example demonstrating X11 forwarding with DartSSH2
Future<void> main() async {
  final socket = await SSHSocket.connect('localhost', 22);
  
  final client = SSHClient(
    socket,
    username: 'user',
    onPasswordRequest: () => 'password',
  );

  try {
    print('Connected to SSH server');

    // Start a session with X11 forwarding
    final session = await client.execute('xeyes');
    
    // Request X11 forwarding
    final x11Success = await session.requestX11Forwarding(
      singleConnection: false,
      authenticationProtocol: 'MIT-MAGIC-COOKIE-1',
      screenNumber: '0',
    );
    
    if (x11Success) {
      print('X11 forwarding enabled successfully');
      print('The xeyes application should now display on your local X server');
    } else {
      print('Failed to enable X11 forwarding');
    }

    // Listen to stdout/stderr
    await for (final data in session.stdout) {
      print('STDOUT: ${String.fromCharCodes(data)}');
    }

    await for (final data in session.stderr) {
      print('STDERR: ${String.fromCharCodes(data)}');
    }

    // Wait for the session to complete
    final exitCode = session.exitCode;
    print('Process exited with code: $exitCode');

  } catch (e) {
    print('Error: $e');
  } finally {
    socket.close();
  }
}
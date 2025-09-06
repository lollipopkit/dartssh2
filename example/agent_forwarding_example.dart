import 'package:dartssh2/dartssh2.dart';

void main() async {
  // Example of using SSH Agent forwarding
  final socket = await SSHSocket.connect('localhost', 22);
  
  final client = SSHClient(
    socket,
    username: 'user',
    enableAgentForwarding: true, // Enable SSH Agent forwarding
    onPasswordRequest: () => 'password',
  );

  try {
    // Execute a command with agent forwarding enabled
    final session = await client.execute('ssh-add -l');
    
    // Read the output
    await for (final data in session.stdout) {
      print(String.fromCharCodes(data));
    }
    
    // Read any errors
    await for (final data in session.stderr) {
      print('Error: ${String.fromCharCodes(data)}');
    }
    
    print('Exit code: ${session.exitCode}');
    
  } catch (e) {
    print('Error: $e');
  } finally {
    client.close();
  }
}
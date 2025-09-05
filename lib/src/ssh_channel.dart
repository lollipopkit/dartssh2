import 'dart:async';
import 'dart:math';

import 'dart:typed_data';

import 'package:dartssh2/src/ssh_channel_id.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:dartssh2/src/utils/async_queue.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/utils/stream.dart';
import 'package:dartssh2/src/ssh_flow_control.dart';

/// Handler of channel requests. Return true if the request was handled, false
/// if the request was not recognized or could not be handled.
typedef SSHChannelRequestHandler = bool Function(
  SSH_Message_Channel_Request request,
);

class SSHChannelController {

  final int localId;
  final int localMaximumPacketSize;
  final int localInitialWindowSize;

  final int remoteId;
  final int remoteMaximumPacketSize;
  final int remoteInitialWindowSize;

  final SSHPrintHandler? printDebug;

  final void Function(SSHMessage) sendMessage;

  /// Enhanced flow control manager
  late final SSHChannelFlowController _flowController;

  SSHChannel get channel => SSHChannel(this);

  SSHChannelController({
    required this.localId,
    required this.localMaximumPacketSize,
    required this.localInitialWindowSize,
    required this.remoteId,
    required this.remoteInitialWindowSize,
    required this.remoteMaximumPacketSize,
    required this.sendMessage,
    this.printDebug,
  }) {
    // Initialize the enhanced flow controller
    _flowController = SSHChannelFlowController(
      initialWindowSize: localInitialWindowSize,
      debugPrint: printDebug,
    );
    
    if (remoteInitialWindowSize > 0) {
      _uploadLoop.activate();
    }
  }

  /// Remaining local receive window size.
  late var _localWindow = localInitialWindowSize;

  /// Remaining remote receive window size.
  late var _remoteWindow = remoteInitialWindowSize;

  /// A [StreamController] that receives data from the remote side.
  late final _remoteStream = StreamController<SSHChannelData>(
    onResume: _sendWindowAdjustIfNeeded,
  );

  /// A [StreamController] that accepts data from local end of the channel.
  final _localStream = StreamController<SSHChannelData>();

  late final _localStreamConsumer = SSHChannelDataConsumer(_localStream.stream);

  /// Handler of channel requests from the remote side.
  late var _requestHandler = _defaultRequestHandler;

  /// An [AsyncQueue] of pending request replies from the remote side.
  final _requestReplyQueue = AsyncQueue<bool>();

  /// true if we have sent an EOF message to the remote side.
  var _hasSentEOF = false;

  /// true if we have sent an close message to the remote side.
  var _hasSentClose = false;

  /// true if the stream is paused due to negative window size
  var _isPausedDueToWindow = false;

  final _done = Completer<void>();

  Future<bool> sendExec(String command) async {
    sendMessage(
      SSH_Message_Channel_Request.exec(
        recipientChannel: remoteId,
        wantReply: true,
        command: command,
      ),
    );
    return await _requestReplyQueue.next;
  }

  Future<bool> sendPtyReq({
    String terminalType = 'xterm-256color',
    int terminalWidth = 80,
    int terminalHeight = 25,
    int terminalPixelWidth = 0,
    int terminalPixelHeight = 0,
    Uint8List? terminalModes,
  }) async {
    sendMessage(
      SSH_Message_Channel_Request.pty(
        recipientChannel: remoteId,
        termType: terminalType,
        termWidth: terminalWidth,
        termHeight: terminalHeight,
        termPixelWidth: terminalPixelWidth,
        termPixelHeight: terminalPixelHeight,
        termModes: terminalModes ?? Uint8List(0),
        wantReply: true,
      ),
    );
    return await _requestReplyQueue.next;
  }

  Future<bool> sendShell() async {
    sendMessage(
      SSH_Message_Channel_Request.shell(
        recipientChannel: remoteId,
        wantReply: true,
      ),
    );
    return await _requestReplyQueue.next;
  }

  Future<bool> sendSubsystem(String subsystem) async {
    sendMessage(
      SSH_Message_Channel_Request.subsystem(
        recipientChannel: remoteId,
        subsystemName: subsystem,
        wantReply: true,
      ),
    );
    return await _requestReplyQueue.next;
  }

  Future<bool> sendX11Req({
    bool singleConnection = false,
    String authenticationProtocol = 'MIT-MAGIC-COOKIE-1',
    String? authenticationCookie,
    String screenNumber = '0',
  }) async {
    // Generate a random cookie if not provided
    final cookie = authenticationCookie ?? _generateX11Cookie();
    
    sendMessage(
      SSH_Message_Channel_Request.x11(
        recipientChannel: remoteId,
        wantReply: true,
        singleConnection: singleConnection,
        x11AuthenticationProtocol: authenticationProtocol,
        x11AuthenticationCookie: cookie,
        x11ScreenNumber: screenNumber,
      ),
    );
    return await _requestReplyQueue.next;
  }

  void sendEnv(String name, String value) {
    sendMessage(
      SSH_Message_Channel_Request.env(
        recipientChannel: remoteId,
        variableName: name,
        variableValue: value,
        wantReply: true,
      ),
    );
  }

  void sendSignal(String signal) {
    sendMessage(
      SSH_Message_Channel_Request.signal(
        recipientChannel: remoteId,
        signalName: signal,
      ),
    );
  }

  Future<bool> sendAuthAgent() async {
    sendMessage(
      SSH_Message_Channel_Request.authAgent(
        recipientChannel: remoteId,
        wantReply: true,
      ),
    );
    return await _requestReplyQueue.next;
  }

  void sendTerminalWindowChange({
    required int width,
    required int height,
    required int pixelWidth,
    required int pixelHeight,
  }) {
    sendMessage(
      SSH_Message_Channel_Request.windowChange(
        recipientChannel: remoteId,
        termWidth: width,
        termHeight: height,
        termPixelWidth: pixelWidth,
        termPixelHeight: pixelHeight,
      ),
    );
  }

  void handleMessage(SSHMessage message) {
    if (message is SSH_Message_Channel_Data) {
      _handleDataMessage(message.data);
    } else if (message is SSH_Message_Channel_Extended_Data) {
      _handleDataMessage(message.data, type: message.dataTypeCode);
    } else if (message is SSH_Message_Channel_Window_Adjust) {
      _handleWindowAdjustMessage(message.bytesToAdd);
    } else if (message is SSH_Message_Channel_EOF) {
      _handleEOFMessage();
    } else if (message is SSH_Message_Channel_Close) {
      _handleCloseMessage();
    } else if (message is SSH_Message_Channel_Request) {
      _handleRequestMessage(message);
    } else if (message is SSH_Message_Channel_Success) {
      _handleRequestSuccessMessage();
    } else if (message is SSH_Message_Channel_Failure) {
      _handleRequestFailureMessage();
    } else {
      throw UnimplementedError('Unimplemented message: $message');
    }
  }

  /// Closes our side of the channel. Returns a [Future] that completes when
  /// the remote side has closed the channel.
  Future<void> close() async {
    if (_done.isCompleted) return;

    _localStreamConsumer.cancel();
    _sendEOFIfNeeded();

    if (_remoteStream.isClosed) {
      _sendCloseIfNeeded();
      _done.complete();
      return;
    }

    return _done.future;
  }

  /// Closes the channel immediately in both directions. This may send a close
  /// message to the remote side. After this no more data can be sent or
  /// received.
  void destroy() {
    if (_done.isCompleted) return;
    _remoteStream.close();
    _localStreamConsumer.cancel();
    _sendEOFIfNeeded();
    _sendCloseIfNeeded();
    _done.complete();
  }

  /// Get current flow control statistics for monitoring and debugging
  Map<String, dynamic> getFlowControlStatistics() {
    return _flowController.getStatistics();
  }

  /// Reset flow control state (useful for connection recovery)
  void resetFlowControl() {
    _flowController.reset();
    _localWindow = _flowController.localWindow;
    _isPausedDueToWindow = false;
  }

  void _handleWindowAdjustMessage(int bytesToAdd) {
    printDebug?.call('SSHChannel._handleWindowAdjustMessage: $bytesToAdd');

    if (bytesToAdd < 0) {
      throw ArgumentError.value(bytesToAdd, 'bytesToAdd', 'must be positive');
    }

    final next = _remoteWindow + bytesToAdd;
    _remoteWindow = next & 0xFFFFFFFF; // 2³²-1 Overflow

    if (_remoteWindow > 0) {
      _uploadLoop.activate();
    }
  }

  void _handleDataMessage(Uint8List data, {int? type}) {
    printDebug?.call('SSHChannel._handleDataMessage: len=${data.length}');

    if (_remoteStream.isClosed) {
      printDebug?.call('SSHChannel._handleDataMessage: remote already closed');
      return;
    }

    // Use flow controller to process incoming data
    _flowController.processIncomingData(data.length);
    
    // Update legacy _localWindow for backwards compatibility
    _localWindow = _flowController.localWindow;

    // If window is negative, don't process more data until window is adjusted
    if (_isPausedDueToWindow && _localWindow < 0) {
      printDebug?.call('SSHChannel._handleDataMessage: stream paused due to negative window, skipping data');
      return;
    }

    _remoteStream.add(SSHChannelData(data, type: type));

    if (_localWindow < 0) {
      // If window goes negative, pause the stream and immediately request window adjustment
      printDebug?.call('SSHChannel._handleDataMessage: window went negative: $_localWindow');
      _isPausedDueToWindow = true;
      _sendWindowAdjustIfNeeded();
    }

    _sendWindowAdjustIfNeeded();
  }

  void _handleRequestMessage(SSH_Message_Channel_Request request) {
    printDebug?.call('SSHChannel._handleRequest: ${request.requestType}');

    final success = _requestHandler(request);
    if (!request.wantReply) return;
    success ? _sendRequestSuccess() : _sendRequestFailure();
  }

  void _handleRequestSuccessMessage() {
    printDebug?.call('SSHChannel._handleRequestSuccessMessage');
    _requestReplyQueue.add(true);
  }

  void _handleRequestFailureMessage() {
    printDebug?.call('SSHChannel._handleRequestFailureMessage');
    _requestReplyQueue.add(false);
  }

  void _handleEOFMessage() {
    printDebug?.call('SSHChannel._handleEOFMessage');
    _remoteStream.close();
  }

  void _handleCloseMessage() {
    printDebug?.call('SSHChannel._handleCLoseMessage');
    _remoteStream.close();
    close();
  }

  bool _defaultRequestHandler(SSH_Message_Channel_Request request) {
    return false;
  }

  void _sendEOFIfNeeded() {
    printDebug?.call('SSHChannel._sendEOFIfNeeded');
    if (_done.isCompleted) return;
    if (_hasSentEOF) return;
    _hasSentEOF = true;
    sendMessage(SSH_Message_Channel_EOF(recipientChannel: remoteId));
  }

  void _sendCloseIfNeeded() {
    printDebug?.call('SSHChannel._sendCloseIfNeeded');
    if (_done.isCompleted) return;
    if (_hasSentClose) return;
    _hasSentClose = true;
    sendMessage(SSH_Message_Channel_Close(recipientChannel: remoteId));
  }

  void _sendRequestSuccess() {
    printDebug?.call('SSHChannel._sendRequestSuccess');
    sendMessage(SSH_Message_Channel_Success(recipientChannel: remoteId));
  }

  void _sendRequestFailure() {
    printDebug?.call('SSHChannel._sendRequestFailure');
    sendMessage(SSH_Message_Channel_Failure(recipientChannel: remoteId));
  }

  void _sendWindowAdjustIfNeeded() {
    printDebug?.call('SSHChannel._sendWindowAdjustIfNeeded');

    if (_done.isCompleted) return;

    // Use the enhanced flow controller to determine if adjustment is needed
    if (!_flowController.needsWindowAdjustment) {
      return;
    }

    // Calculate optimal window adjustment using adaptive algorithm
    final bytesToAdd = _flowController.calculateWindowAdjustment();
    
    if (bytesToAdd <= 0) {
      return;
    }

    // Update legacy _localWindow for backwards compatibility
    _localWindow = _flowController.localWindow;

    sendMessage(SSH_Message_Channel_Window_Adjust(
      recipientChannel: remoteId,
      bytesToAdd: bytesToAdd,
    ));

    // If the stream was paused due to negative window, reset the flag
    if (_isPausedDueToWindow) {
      _isPausedDueToWindow = false;
    }
    
    // Log flow control statistics periodically
    final stats = _flowController.getStatistics();
    printDebug?.call('SSHChannel: Flow control stats - BW: ${stats['estimatedBandwidth']}, RTT: ${stats['estimatedRtt']}, Window: ${stats['currentWindowSize']}');
  }

  late final _uploadLoop = OnceSimultaneously(() async {
    while (true) {
      if (_remoteWindow <= 0) {
        return;
      }

      final dataToRead = min(_remoteWindow, remoteMaximumPacketSize);
      final data = await _localStreamConsumer.read(dataToRead);

      if (data == null) {
        _sendEOFIfNeeded();

        if (_remoteStream.isClosed) {
          close();
        }
        return;
      }

      if (_hasSentEOF) {
        return;
      }

      printDebug?.call('SSHChannel._uploadLoop: len=${data.bytes.length}');

      final message = data.isExtendedData
          ? SSH_Message_Channel_Extended_Data(
              recipientChannel: remoteId,
              dataTypeCode: data.type!,
              data: data.bytes,
            )
          : SSH_Message_Channel_Data(
              recipientChannel: remoteId,
              data: data.bytes,
            );

      sendMessage(message);

      _remoteWindow -= data.bytes.length;
    }
  });

  /// Generate a random X11 authentication cookie
  String _generateX11Cookie() {
    final random = Random.secure();
    final bytes = Uint8List(16);
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
  }
}

class SSHChannel {
  /// The channel id on the local side.
  SSHChannelId get channelId => _controller.localId;

  /// The channel id on the remote side.
  SSHChannelId get remoteChannelId => _controller.localId;

  /// The maximum packet size that the remote side can receive.
  int get maximumPacketSize => _controller.remoteMaximumPacketSize;

  /// A [Stream] of data received from the remote side.
  Stream<SSHChannelData> get stream => _controller._remoteStream.stream;

  /// A [StreamSink] that sends data to the remote side. Chucks must be
  /// equal to or less than [maximumPacketSize].
  StreamSink<SSHChannelData> get sink => _controller._localStream.sink;

  Future<void> get done => _controller._done.future;

  SSHChannel(this._controller);

  final SSHChannelController _controller;

  /// Send data to the remote side.
  void addData(Uint8List data, {int? type}) {
    sink.add(SSHChannelData(data, type: type));
  }

  void setRequestHandler(SSHChannelRequestHandler handler) {
    _controller._requestHandler = handler;
  }

  Future<bool> sendExec(String command) async {
    return await _controller.sendExec(command);
  }

  Future<bool> sendShell() async {
    return await _controller.sendShell();
  }

  void sendTerminalWindowChange({
    required int width,
    required int height,
    int pixelWidth = 0,
    int pixelHeight = 0,
  }) {
    _controller.sendTerminalWindowChange(
      width: width,
      height: height,
      pixelWidth: pixelWidth,
      pixelHeight: pixelHeight,
    );
  }

  void sendSignal(String signal) {
    _controller.sendSignal(signal);
  }

  Future<bool> sendAuthAgent() async {
    return await _controller.sendAuthAgent();
  }

  Future<bool> sendX11Req({
    bool singleConnection = false,
    String authenticationProtocol = 'MIT-MAGIC-COOKIE-1',
    String? authenticationCookie,
    String screenNumber = '0',
  }) async {
    return await _controller.sendX11Req(
      singleConnection: singleConnection,
      authenticationProtocol: authenticationProtocol,
      authenticationCookie: authenticationCookie,
      screenNumber: screenNumber,
    );
  }

  /// Closes our side of the channel. Returns a [Future] that completes when
  /// both sides of the channel are closed.
  Future<void> close() {
    _controller._sendEOFIfNeeded();
    return _controller.close();
  }

  /// Destroys the channel in both directions. After calling this method,
  /// no more data can be sent or received.
  void destroy() => _controller.destroy();

  /// Get current flow control statistics for performance monitoring
  Map<String, dynamic> getFlowControlStatistics() {
    return _controller.getFlowControlStatistics();
  }

  /// Reset flow control state (useful for connection recovery scenarios)
  void resetFlowControl() {
    _controller.resetFlowControl();
  }

  @override
  String toString() => 'SSHChannel($channelId:$remoteChannelId)';
}

class SSHChannelData {
  /// Type of the data. Not null if the data is extended data. See: [SSHChannelExtendedDataType]
  final int? type;

  final Uint8List bytes;

  bool get isExtendedData => type != null;

  SSHChannelData(this.bytes, {this.type});
}

class SSHChannelExtendedDataType {
  static const stderr = 1;
}

class SSHChannelDataSplitter extends StreamTransformerBase<SSHChannelData, SSHChannelData> {
  SSHChannelDataSplitter(this.maxSize);

  final int maxSize;

  @override
  Stream<SSHChannelData> bind(Stream<SSHChannelData> stream) async* {
    await for (var chunk in stream) {
      if (chunk.bytes.length < maxSize) {
        yield chunk;
        continue;
      }

      final blocks = chunk.bytes.length ~/ maxSize;

      for (var i = 0; i < blocks; i++) {
        yield SSHChannelData(
          Uint8List.sublistView(chunk.bytes, i * maxSize, (i + 1) * maxSize),
          type: chunk.type,
        );
      }

      if (blocks * maxSize < chunk.bytes.length) {
        yield SSHChannelData(
          Uint8List.sublistView(chunk.bytes, blocks * maxSize),
          type: chunk.type,
        );
      }
    }
  }
}

class SSHChannelDataConsumer extends StreamConsumerBase<SSHChannelData> {
  SSHChannelDataConsumer(super.stream);

  @override
  int getLength(SSHChannelData chunk) {
    return chunk.bytes.length;
  }

  @override
  SSHChannelData getSublistView(SSHChannelData chunk, int start, int end) {
    return SSHChannelData(
      Uint8List.sublistView(chunk.bytes, start, end),
      type: chunk.type,
    );
  }
}

/// A function that can be invoked at most once simultaneously.
class OnceSimultaneously {
  OnceSimultaneously(this._fn);

  final Future Function() _fn;

  var _isRunning = false;

  /// Call the function. If the function is already running, this is a no-op.
  void activate() async {
    if (_isRunning) return;
    _isRunning = true;
    try {
      await _fn();
    } finally {
      _isRunning = false;
    }
  }
}

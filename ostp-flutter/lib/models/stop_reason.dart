/// What to tell the user when the tunnel stopped by itself.
///
/// The core's metrics carry `stop_reason`: plain words, set when the server
/// closed the session on purpose (key revoked, traffic limit used up, and so
/// on) and empty otherwise. Without it the stop is a failed or lost connection.
String stoppedMessage(Object? stopReason) {
  final text = stopReason is String ? stopReason.trim() : '';
  return text.isNotEmpty ? text : 'Could not connect to the server. See Logs for the reason.';
}

/// A reason from the server is a sentence or two: it stays on screen longer
/// than a one-line notice.
Duration stoppedMessageDuration(Object? stopReason) {
  final text = stopReason is String ? stopReason.trim() : '';
  return text.isNotEmpty ? const Duration(seconds: 12) : const Duration(seconds: 4);
}

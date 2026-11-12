/// Subscriptions that limit devices: how the core's answer is read.
///
/// The core reports a refusal as the text `device:<code>:<server message>` where
/// `<code>` is `hwid_required` or `device_limit`. Anything else is an ordinary error.
library;

/// Preference key of "Send a device ID to subscriptions" (default off).
const sendHwidKey = 'send_hwid';

enum FetchErrorKind { hwidRequired, deviceLimit, other }

class FetchError {
  final FetchErrorKind kind;
  final String message;
  const FetchError(this.kind, this.message);
}

/// Maps the error text of a failed subscription fetch.
FetchError classifyFetchError(String raw) {
  const prefix = 'device:';
  if (raw.startsWith(prefix)) {
    final rest = raw.substring(prefix.length);
    final i = rest.indexOf(':');
    final code = i < 0 ? rest : rest.substring(0, i);
    final message = i < 0 ? '' : rest.substring(i + 1).trim();
    if (code == 'hwid_required') return FetchError(FetchErrorKind.hwidRequired, message);
    if (code == 'device_limit') return FetchError(FetchErrorKind.deviceLimit, message);
  }
  return FetchError(FetchErrorKind.other, raw);
}

/// The line on the subscription card and in the snackbar for a failed fetch.
String fetchErrorText(FetchError e) => e.kind == FetchErrorKind.hwidRequired
    ? 'Device ID needed: turn on "Send a device ID to subscriptions" in settings'
    : e.message;

/// A fetch refused because of the device limit. Its text is what the card shows.
class DeviceLimitException implements Exception {
  final FetchError error;
  const DeviceLimitException(this.error);

  bool get needsId => error.kind == FetchErrorKind.hwidRequired;

  @override
  String toString() => fetchErrorText(error);
}

/// Whether a failed fetch may ask the person about sending an ID: only when
/// they started it, the server asked for one, sending is off, and not twice.
bool shouldAskToSend({required FetchError error, required bool manual, required bool sendOn, bool retried = false}) =>
    error.kind == FetchErrorKind.hwidRequired && manual && !sendOn && !retried;

const sendDialogTitle = 'This subscription limits devices';
const sendDialogText = "The server needs this device's ID to count it. Send it?";
const sendDialogOk = 'Send and retry';

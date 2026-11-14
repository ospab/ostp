import 'package:flutter_test/flutter_test.dart';

import 'package:ostp_client/models/device_limit.dart';

void main() {
  test('the core answer is mapped to a kind and the server message', () {
    final a = classifyFetchError('device:hwid_required:This subscription limits devices.');
    expect(a.kind, FetchErrorKind.hwidRequired);
    expect(a.message, 'This subscription limits devices.');

    final b = classifyFetchError('device:device_limit:3 of 3: devices');
    expect(b.kind, FetchErrorKind.deviceLimit);
    expect(b.message, '3 of 3: devices');

    expect(classifyFetchError('device:hwid_required').kind, FetchErrorKind.hwidRequired);
    expect(classifyFetchError('device:unknown:x').kind, FetchErrorKind.other);
    final c = classifyFetchError('the server answered HTTP 500');
    expect(c.kind, FetchErrorKind.other);
    expect(c.message, 'the server answered HTTP 500');
  });

  test('card and snackbar text', () {
    expect(
      fetchErrorText(classifyFetchError('device:hwid_required:x')),
      'Device ID needed: turn on "Send a device ID to subscriptions" in settings',
    );
    expect(fetchErrorText(classifyFetchError('device:device_limit:Limit reached')), 'Limit reached');
    expect(fetchErrorText(classifyFetchError('boom')), 'boom');
    expect(DeviceLimitException(classifyFetchError('device:device_limit:Limit reached')).toString(), 'Limit reached');
    expect(DeviceLimitException(classifyFetchError('device:hwid_required:x')).needsId, true);
  });

  test('the dialog is only for a fetch started by hand, once, while sending is off', () {
    final need = classifyFetchError('device:hwid_required:x');
    expect(shouldAskToSend(error: need, manual: true, sendOn: false), true);
    expect(shouldAskToSend(error: need, manual: false, sendOn: false), false, reason: 'never in the background');
    expect(shouldAskToSend(error: need, manual: true, sendOn: true), false);
    expect(shouldAskToSend(error: need, manual: true, sendOn: false, retried: true), false);
    expect(shouldAskToSend(error: classifyFetchError('device:device_limit:x'), manual: true, sendOn: false), false);
  });
}

import 'package:flutter_test/flutter_test.dart';

import 'package:ostp_client/models/stop_reason.dart';

void main() {
  test('the server\'s reason is shown as it came, and stays longer', () {
    const reason = 'The server closed the connection: your key was revoked or removed. Ask the server owner for a new key.';
    expect(stoppedMessage(reason), reason);
    expect(stoppedMessage('  $reason \n'), reason);
    expect(stoppedMessageDuration(reason), const Duration(seconds: 12));
  });

  test('without a reason it is the old notice', () {
    for (final none in [null, '', '   ', 5]) {
      expect(stoppedMessage(none), 'Could not connect to the server. See Logs for the reason.');
      expect(stoppedMessageDuration(none), const Duration(seconds: 4));
    }
  });
}

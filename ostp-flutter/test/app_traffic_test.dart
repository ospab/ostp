import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:ostp_client/models/app_traffic.dart';

void main() {
  test('the app\'s own requests use the tunnel by default', () async {
    SharedPreferences.setMockInitialValues({});
    final prefs = await SharedPreferences.getInstance();
    expect(appViaTunnel(prefs), true);
    await prefs.setBool(appViaTunnelKey, false);
    expect(appViaTunnel(prefs), false);
    await prefs.setBool(appViaTunnelKey, true);
    expect(appViaTunnel(prefs), true);
  });
}

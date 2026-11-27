/// Where the app's own requests (subscription refreshes, update checks and the update
/// download) go: through the tunnel when it is up, or straight out.
library;

import 'package:shared_preferences/shared_preferences.dart';

/// Preference key of "Use the tunnel for subscriptions and updates" (default on).
const appViaTunnelKey = 'app_via_tunnel';

/// On unless the person turned it off. The native side uses the tunnel only while it is
/// connected; with the tunnel down the request goes direct, as before. A failure through
/// the tunnel is shown as an error and is not retried outside it.
bool appViaTunnel(SharedPreferences prefs) => prefs.getBool(appViaTunnelKey) ?? true;

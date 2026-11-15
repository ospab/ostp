/// What this device's log may say. `normal` (the default) writes no sites or
/// DNS names; `debug` writes them, with full addresses. The core also knows
/// `strict`, which on a client is the same as `normal`.
library;

import 'package:shared_preferences/shared_preferences.dart';

/// Preference key of the log privacy mode, `normal` or `debug`.
const logPrivacyKey = 'log_privacy';

/// The saved mode. Before this setting there was an on/off "Debug Mode"
/// (`debug_mode`); on keeps meaning `debug`.
String logPrivacyOf(SharedPreferences p) {
  final saved = p.getString(logPrivacyKey);
  if (saved == 'debug' || saved == 'normal') return saved!;
  return (p.getBool('debug_mode') ?? false) ? 'debug' : 'normal';
}

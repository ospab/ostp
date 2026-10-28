import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

/// Update check shared by the start-up check and the button in settings.
/// The native core knows this build's release tag (e.g. v0.4.6-beta.2) and
/// compares it with GitHub releases: the newest stable newer than this
/// build, and a beta only when it is newer than that stable.

const _channel = MethodChannel('com.ospab.ostp/vpn');

/// Preference: check when the app opens (default on).
const autoUpdateCheckKey = 'auto_update_check';
const _skipKey = 'skip_update_tag';

/// This build's release tag, e.g. "v0.4.6-beta.2", or null if unknown.
Future<String?> buildTag() async {
  try {
    return await _channel.invokeMethod<String>('buildTag').timeout(const Duration(seconds: 5));
  } catch (_) {
    return null;
  }
}

/// Checks GitHub. `manual` also reports "up to date" and failures, and
/// ignores a skipped version.
Future<void> checkForUpdates(BuildContext context, SharedPreferences prefs, {required bool manual}) async {
  Map<String, dynamic> r;
  try {
    final raw = await _channel.invokeMethod<String>('checkForUpdates').timeout(const Duration(seconds: 30));
    r = jsonDecode(raw ?? '{}') as Map<String, dynamic>;
    if (r['error'] != null) throw Exception(r['error']);
  } on TimeoutException {
    if (manual && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Update check failed: no answer in time')));
    }
    return;
  } catch (e) {
    if (manual && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Update check failed: ${e.toString().replaceFirst('Exception: ', '')}')),
      );
    }
    return;
  }
  final offer = (r['beta'] ?? r['stable']) as Map<String, dynamic>?;
  if (offer == null) {
    if (manual && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('You have the latest version (${r['current']})')));
    }
    return;
  }
  if (!manual && prefs.getString(_skipKey) == offer['tag']) return;
  if (!context.mounted) return;

  final isBeta = offer['channel'] == 'beta';
  final stable = r['stable'] as Map<String, dynamic>?;
  await showDialog(
    context: context,
    builder: (context) => AlertDialog(
      backgroundColor: Theme.of(context).colorScheme.surface,
      title: Text(isBeta ? 'Beta version available' : 'Update available'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('${offer['tag']} is out. You have ${r['current']}.'
              '${isBeta && stable != null ? ' The newest stable release is ${stable['tag']}.' : ''}'),
          if (isBeta) ...[
            const SizedBox(height: 12),
            const Text(
              'This is a beta: new features that are still being tested. It can be less stable than '
              'the release you have; keep the previous APK in case you need to go back.',
              style: TextStyle(color: Colors.orangeAccent, fontSize: 13),
            ),
          ],
        ],
      ),
      actions: [
        TextButton(
          onPressed: () {
            prefs.setString(_skipKey, offer['tag'] as String);
            Navigator.pop(context);
          },
          child: const Text('Skip this version'),
        ),
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Later')),
        TextButton(
          onPressed: () {
            Navigator.pop(context);
            _openReleasePage(offer['url'] as String);
          },
          child: const Text('Release page'),
        ),
        TextButton(
          onPressed: () {
            Navigator.pop(context);
            _updateNow(context, offer['tag'] as String, offer['url'] as String);
          },
          child: const Text('Update now'),
        ),
      ],
    ),
  );
}

void _openReleasePage(String url) => launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);

String _reason(Object e) {
  if (e is PlatformException) return e.message ?? e.code;
  return e.toString().replaceFirst('Exception: ', '');
}

/// Downloads the APK of [tag] (checked against the SHA-256 GitHub publishes),
/// then hands it to the system installer. Runs only after the user tapped
/// "Update now"; on any failure it says why and offers the release page.
Future<void> _updateNow(BuildContext context, String tag, String releaseUrl) async {
  final progress = ValueNotifier<double?>(null);
  var cancelled = false;
  final navigator = Navigator.of(context, rootNavigator: true);
  // Dialog state, not awaited: the download below runs while it is open.
  showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (context) => AlertDialog(
      title: Text('Downloading $tag'),
      content: ValueListenableBuilder<double?>(
        valueListenable: progress,
        builder: (context, value, _) => Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            LinearProgressIndicator(value: value),
            const SizedBox(height: 8),
            Text(value == null ? 'Starting...' : '${(value * 100).round()}%'),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () {
            cancelled = true;
            _channel.invokeMethod('cancelUpdate');
          },
          child: const Text('Cancel'),
        ),
      ],
    ),
  );

  final poll = Timer.periodic(const Duration(milliseconds: 400), (_) async {
    try {
      final p = await _channel.invokeMapMethod<String, dynamic>('updateProgress');
      final total = (p?['total'] as num?)?.toInt() ?? 0;
      if (total > 0) progress.value = ((p!['downloaded'] as num).toInt() / total).clamp(0.0, 1.0);
    } catch (_) {}
  });

  String? path;
  String? failure;
  try {
    path = await _channel.invokeMethod<String>('downloadUpdate', {'tag': tag});
  } catch (e) {
    failure = _reason(e);
  }
  poll.cancel();
  navigator.pop();
  if (cancelled) return;
  if (!context.mounted) return;
  if (path == null) {
    await _showFailure(context, failure ?? 'The download returned no file', releaseUrl);
    return;
  }
  await _install(context, path, releaseUrl);
}

Future<void> _install(BuildContext context, String path, String releaseUrl) async {
  bool started;
  try {
    started = await _channel.invokeMethod<bool>('installUpdate', {'path': path}) ?? false;
  } catch (e) {
    if (context.mounted) await _showFailure(context, _reason(e), releaseUrl);
    return;
  }
  if (started || !context.mounted) return;
  // Android opened the settings screen for "install unknown apps".
  await showDialog<void>(
    context: context,
    builder: (dialogContext) => AlertDialog(
      title: const Text('Allow installing updates'),
      content: const Text(
        'Android needs your permission to install apps from OSTP. Turn on "Allow from this source" '
        'in the settings screen that just opened, come back and press Install.',
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(dialogContext), child: const Text('Cancel')),
        TextButton(
          onPressed: () {
            Navigator.pop(dialogContext);
            _install(context, path, releaseUrl);
          },
          child: const Text('Install'),
        ),
      ],
    ),
  );
}

Future<void> _showFailure(BuildContext context, String reason, String releaseUrl) {
  return showDialog<void>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('The update was not installed'),
      content: Text(reason),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close')),
        TextButton(
          onPressed: () {
            Navigator.pop(context);
            _openReleasePage(releaseUrl);
          },
          child: const Text('Release page'),
        ),
      ],
    ),
  );
}

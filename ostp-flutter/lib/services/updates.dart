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
    return await _channel.invokeMethod<String>('buildTag');
  } catch (_) {
    return null;
  }
}

/// Checks GitHub. `manual` also reports "up to date" and failures, and
/// ignores a skipped version.
Future<void> checkForUpdates(BuildContext context, SharedPreferences prefs, {required bool manual}) async {
  Map<String, dynamic> r;
  try {
    final raw = await _channel.invokeMethod<String>('checkForUpdates');
    r = jsonDecode(raw ?? '{}') as Map<String, dynamic>;
    if (r['error'] != null) throw Exception(r['error']);
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
            launchUrl(Uri.parse(offer['url'] as String), mode: LaunchMode.externalApplication);
          },
          child: const Text('Download'),
        ),
      ],
    ),
  );
}

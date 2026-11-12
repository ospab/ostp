import 'package:flutter/material.dart';

import '../models/device_limit.dart';

/// Shown when a subscription the person fetched by hand needs a device ID and
/// sending it is off. True = turn sending on and retry once.
Future<bool> askSendDeviceId(BuildContext context) async {
  final send = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: Theme.of(ctx).colorScheme.surface,
      title: const Text(sendDialogTitle),
      content: const Text(sendDialogText),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
        TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text(sendDialogOk)),
      ],
    ),
  );
  return send ?? false;
}

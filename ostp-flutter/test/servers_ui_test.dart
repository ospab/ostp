import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:ostp_client/models/ostp_profile.dart';
import 'package:ostp_client/ui/servers_screen.dart';
import 'package:ostp_client/ui/welcome_screen.dart';

/// The native core's answers, as ostp-jni's `serversCall` gives them.
const _server = {
  'id': 's1', 'name': 'Amsterdam', 'host': '203.0.113.10', 'port': 22, 'user': 'root',
  'auth': 'password', 'host_key': 'SHA256:q2N5x0kGdw5TtJm5y1lCq3S1vD1b0mDFN1z2c3YxW8Q', 'remembered': true, 'added_at': 0,
};
const _users = [
  {
    'number': 1, 'name': 'me', 'key': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'links': [{'label': 'UDP', 'uri': 'ostp://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@203.0.113.10:50000?type=udp'}],
    'subscription': null, 'bytes_up': 12345678, 'bytes_down': 987654321, 'online': true, 'last_seen': 1, 'limit_bytes': null,
  },
  {
    'number': 2, 'name': "mom's phone with a very long name indeed", 'key': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'links': [{'label': 'UDP', 'uri': 'ostp://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb@203.0.113.10:50000?type=udp'}],
    'subscription': null, 'bytes_up': null, 'bytes_down': null, 'online': null, 'last_seen': null, 'limit_bytes': 50000000000,
  },
];
const _status = {
  'version': '0.4.6', 'service': {'registered': true, 'active': true, 'enabled': true, 'started_at': 1},
  'sessions': 3, 'users': 2, 'listen': '0.0.0.0:50000', 'udp_port': 50000,
  'tls': {'enabled': true, 'domain': 'vpn.example.com', 'frontend': 'builtin', 'cert_days_left': 64, 'cert_self_signed': false},
  'subscription': true, 'panel': {'enabled': false, 'bind': '127.0.0.1:9090', 'webpath': '', 'login': false},
  'system': {
    'os': 'Ubuntu 24.04.1 LTS', 'arch': 'x86_64', 'cpus': 2, 'uptime_secs': 1234567, 'load': [0.12, 0.2, 0.1],
    'mem_total': 2000000000, 'mem_available': 1200000000, 'disk_total': 40000000000, 'disk_free': 31000000000,
  },
};

final requests = <Map<String, dynamic>>[];
Map<String, dynamic> panelState = {'enabled': false, 'bind': '127.0.0.1:9090', 'webpath': '', 'login': false};

Object? _answer(Map<String, dynamic> req) {
  switch (req['op']) {
    case 'list':
      return {'servers': [_server], 'can_remember': true};
    case 'lines':
      return {'lines': [], 'next': 0};
    case 'manage':
      final args = (req['args'] as List).cast<String>();
      if (args.first == 'status') return {..._status, 'panel': panelState};
      if (args.first == 'users') return {'users': _users, 'stats_at': 1700000000};
      return {'lines': ['2026-09-27T10:00:00 server started']};
    default:
      return null;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    requests.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('com.ospab.ostp/vpn'), (call) async {
      if (call.method == 'serversCall') {
        final req = jsonDecode((call.arguments as Map)['requestJson'] as String) as Map<String, dynamic>;
        requests.add(req);
        return jsonEncode({'ok': _answer(req)});
      }
      if (call.method == 'isRunning') return false;
      return null;
    });
  });

  Future<SharedPreferences> prefs([Map<String, Object> values = const {}]) async {
    SharedPreferences.setMockInitialValues(values);
    return SharedPreferences.getInstance();
  }

  Future<void> phone(WidgetTester tester) async {
    tester.view.physicalSize = const Size(360 * 3, 740 * 3);
    tester.view.devicePixelRatio = 3;
    addTearDown(tester.view.reset);
  }

  testWidgets('first run opens on the welcome screen, a set-up app does not', (tester) async {
    expect(needsWelcome(await prefs()), isTrue);
    final withProfile = await prefs({
      'profiles_json': encodeProfiles([OstpProfile(id: '1', name: 'x', serverAddr: 'h:1', accessKey: 'k')]),
    });
    expect(needsWelcome(withProfile), isFalse);
    expect(needsWelcome(await prefs({welcomedKey: true})), isFalse);
  });

  testWidgets('welcome screen lays out on a phone and switches to a key', (tester) async {
    await phone(tester);
    await tester.pumpWidget(MaterialApp(theme: ThemeData.dark(useMaterial3: true), home: WelcomeScreen(prefs: await prefs())));
    await tester.pumpAndSettle();
    expect(find.text("Let's get started"), findsOneWidget);
    // Step 1 is only the choice, in this order; nothing to fill in yet.
    final order = ['I have a link', 'I have a QR code', 'I have a server', 'The project on GitHub']
        .map((t) => tester.getTopLeft(find.text(t)).dy)
        .toList();
    expect(order, [...order]..sort());
    expect(find.byType(TextField), findsNothing);
    await tester.tap(find.text('I have a server'));
    await tester.pumpAndSettle();
    expect(find.text('Your server'), findsOneWidget);
    expect(find.text('Install OSTP'), findsOneWidget);
    await tester.scrollUntilVisible(find.text('Install OSTP'), 200, scrollable: find.byType(Scrollable).first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Private key'));
    await tester.pumpAndSettle();
    expect(find.text('Key passphrase (if it has one)'), findsOneWidget);
    // Validation happens before anything is sent.
    await tester.scrollUntilVisible(find.text('Install OSTP'), 200, scrollable: find.byType(Scrollable).first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Install OSTP'));
    await tester.pumpAndSettle();
    expect(find.text('Enter the server address'), findsOneWidget);
    expect(requests.where((r) => r['op'] == 'add'), isEmpty);
  });

  testWidgets('a link on the welcome screen becomes the active profile', (tester) async {
    await phone(tester);
    final p = await prefs();
    await tester.pumpWidget(MaterialApp(home: WelcomeScreen(prefs: p)));
    await tester.tap(find.text('I have a link'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).first, 'ostp://cccccccccccccccccccccccccccccccc@198.51.100.4:50000?type=udp&name=Home');
    await tester.tap(find.text('Add'));
    await tester.pump();
    final profiles = decodeProfiles(p.getString('profiles_json'));
    expect(profiles.single.name, 'Home');
    expect(profiles.single.active, isTrue);
    expect(p.getBool(welcomedKey), isTrue);
  });

  testWidgets('server screen shows every tab without overflowing', (tester) async {
    await phone(tester);
    final p = await prefs();
    await tester.pumpWidget(MaterialApp(theme: ThemeData.dark(useMaterial3: true), home: ServerScreen(prefs: p, server: _server)));
    await tester.pumpAndSettle();
    expect(find.text('RUNNING'), findsOneWidget);
    expect(find.text('Ubuntu 24.04.1 LTS'), findsOneWidget);

    await tester.tap(find.widgetWithText(Tab, 'Users'));
    await tester.pumpAndSettle();
    expect(find.text('me'), findsOneWidget);
    expect(find.textContaining('941.9 MiB', findRichText: true), findsOneWidget);
    // A user opens in its own screen; "Add to this app" there imports the
    // user's links as profiles.
    await tester.tap(find.text('me'));
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Add to this app').first);
    await tester.pumpAndSettle();
    expect(decodeProfiles(p.getString('profiles_json')).single.name, 'Amsterdam · me · UDP');
    await tester.pageBack();
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(Tab, 'Connection'));
    await tester.pumpAndSettle();
    expect(find.textContaining(RegExp('64 days left', caseSensitive: false), findRichText: true), findsOneWidget);

    await tester.tap(find.widgetWithText(Tab, 'Management'));
    await tester.pumpAndSettle();
    expect(find.text('Turn on the panel'), findsOneWidget);
    await tester.tap(find.text('Show the last 300 lines'));
    await tester.pumpAndSettle();
    expect(find.textContaining('server started'), findsOneWidget);
  });

  testWidgets('an enabled panel offers its address through the VPN', (tester) async {
    await phone(tester);
    panelState = {'enabled': true, 'bind': '127.0.0.1:9191', 'webpath': '/secret/', 'login': true};
    addTearDown(() => panelState = {'enabled': false, 'bind': '127.0.0.1:9090', 'webpath': '', 'login': false});
    await tester.pumpWidget(MaterialApp(home: ServerScreen(prefs: await prefs(), server: _server)));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(Tab, 'Management'));
    await tester.pumpAndSettle();
    expect(find.text('Open the panel'), findsOneWidget);
    expect(find.text('http://10.1.0.1:9191/secret/'), findsOneWidget);
  });

  testWidgets('an empty webpath is the default /panel/, not the site root', (tester) async {
    await phone(tester);
    panelState = {'enabled': true, 'bind': '127.0.0.1:9090', 'webpath': '', 'login': true};
    addTearDown(() => panelState = {'enabled': false, 'bind': '127.0.0.1:9090', 'webpath': '', 'login': false});
    await tester.pumpWidget(MaterialApp(home: ServerScreen(prefs: await prefs(), server: _server)));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(Tab, 'Management'));
    await tester.pumpAndSettle();
    expect(find.text('http://10.1.0.1:9090/panel/'), findsOneWidget);
  });

  testWidgets('servers list opens a server', (tester) async {
    await phone(tester);
    await tester.pumpWidget(MaterialApp(home: ServersScreen(prefs: await prefs())));
    await tester.pumpAndSettle();
    expect(find.text('Amsterdam'), findsOneWidget);
    await tester.tap(find.text('Amsterdam'));
    await tester.pumpAndSettle();
    expect(find.text('Status'), findsOneWidget);
  });
}

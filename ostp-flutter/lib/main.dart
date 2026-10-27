import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'ui/home_screen.dart';
import 'ui/welcome_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final prefs = await SharedPreferences.getInstance();
  runApp(OstpApp(prefs: prefs));
}

class OstpApp extends StatelessWidget {
  final SharedPreferences prefs;
  const OstpApp({super.key, required this.prefs});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OSTP Client',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF000000),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFFFFFFFF),
          secondary: Color(0xFFAAAAAA),
          surface: Color(0xFF111111),
        ),
        fontFamily: 'Inter',
        useMaterial3: true,
      ),
      home: needsWelcome(prefs) ? WelcomeScreen(prefs: prefs) : HomeScreen(prefs: prefs),
    );
  }
}

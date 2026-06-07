import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

class AppRoutingScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const AppRoutingScreen({super.key, required this.prefs});

  @override
  State<AppRoutingScreen> createState() => _AppRoutingScreenState();
}

class _AppRoutingScreenState extends State<AppRoutingScreen> {
  static const platform = MethodChannel('com.ospab.ostp/vpn');
  
  List<Map<String, dynamic>> _allApps = [];
  List<Map<String, dynamic>> _filteredApps = [];
  Set<String> _selectedPackages = {};
  String _routingMode = 'bypass';
  bool _hideSystemApps = true;
  bool _isLoading = true;
  String _searchQuery = '';
  
  final TextEditingController _searchCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _loadSavedConfig();
    _fetchInstalledApps();
  }

  void _loadSavedConfig() {
    setState(() {
      _routingMode = widget.prefs.getString('app_routing_mode') ?? 'bypass';
      _selectedPackages = (widget.prefs.getStringList('app_routing_packages') ?? []).toSet();
    });
  }

  Future<void> _fetchInstalledApps() async {
    try {
      final List<dynamic>? rawApps = await platform.invokeMethod('getInstalledApps');
      if (rawApps != null) {
        final List<Map<String, dynamic>> apps = rawApps.map((e) {
          final Map<dynamic, dynamic> m = e as Map<dynamic, dynamic>;
          return {
            "name": m["name"] as String? ?? "Unknown",
            "package": m["package"] as String? ?? "",
            "isSystem": m["isSystem"] as bool? ?? false,
            "icon": m["icon"] as String? ?? "",
          };
        }).toList();
        
        apps.sort((a, b) => (a["name"] as String).toLowerCase().compareTo((b["name"] as String).toLowerCase()));
        
        setState(() {
          _allApps = apps;
          _isLoading = false;
        });
        _filterApps();
      }
    } catch (e) {
      debugPrint("Error fetching apps: $e");
      setState(() => _isLoading = false);
    }
  }

  void _filterApps() {
    setState(() {
      _filteredApps = _allApps.where((app) {
        final name = (app["name"] as String).toLowerCase();
        final package = (app["package"] as String).toLowerCase();
        final query = _searchQuery.toLowerCase();
        
        final matchesSearch = name.contains(query) || package.contains(query);
        final matchesSystemFilter = !_hideSystemApps || !(app["isSystem"] as bool);
        
        return matchesSearch && matchesSystemFilter;
      }).toList();
    });
  }

  void _saveConfig() {
    widget.prefs.setString('app_routing_mode', _routingMode);
    widget.prefs.setStringList('app_routing_packages', _selectedPackages.toList());
  }

  void _resetConfig() {
    setState(() {
      _selectedPackages.clear();
      _routingMode = 'bypass';
      _hideSystemApps = true;
      _searchCtrl.clear();
      _searchQuery = '';
    });
    _saveConfig();
    _filterApps();
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('App routing rules reset successfully')),
    );
  }

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('App Routing Rules', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18)),
        backgroundColor: theme.colorScheme.surface,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            tooltip: 'Reset Rules',
            onPressed: _resetConfig,
          ),
        ],
      ),
      body: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            color: theme.colorScheme.surface.withOpacity(0.5),
            child: Column(
              children: [
                Row(
                  children: [
                    Expanded(
                      child: GestureDetector(
                        onTap: () {
                          setState(() {
                            _routingMode = 'bypass';
                          });
                          _saveConfig();
                        },
                        child: Container(
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          decoration: BoxDecoration(
                            color: _routingMode == 'bypass' ? theme.colorScheme.primary : Colors.white.withOpacity(0.05),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                              color: _routingMode == 'bypass' ? theme.colorScheme.primary : Colors.white.withOpacity(0.1),
                            ),
                          ),
                          child: const Center(
                            child: Text(
                              'Bypass Mode',
                              style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white),
                            ),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: GestureDetector(
                        onTap: () {
                          setState(() {
                            _routingMode = 'proxy';
                          });
                          _saveConfig();
                        },
                        child: Container(
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          decoration: BoxDecoration(
                            color: _routingMode == 'proxy' ? theme.colorScheme.secondary : Colors.white.withOpacity(0.05),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                              color: _routingMode == 'proxy' ? theme.colorScheme.secondary : Colors.white.withOpacity(0.1),
                            ),
                          ),
                          child: const Center(
                            child: Text(
                              'Proxy Mode',
                              style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  _routingMode == 'bypass' 
                      ? 'Selected apps bypass the VPN (direct connection).' 
                      : 'Only selected apps are routed through the VPN.',
                  style: const TextStyle(fontSize: 13, color: Colors.white54),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
          
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _searchCtrl,
                    onChanged: (val) {
                      setState(() {
                        _searchQuery = val;
                      });
                      _filterApps();
                    },
                    decoration: InputDecoration(
                      hintText: 'Search apps...',
                      prefixIcon: const Icon(Icons.search_rounded, color: Colors.white54),
                      suffixIcon: _searchQuery.isNotEmpty ? IconButton(
                        icon: const Icon(Icons.clear_rounded, color: Colors.white54),
                        onPressed: () {
                          _searchCtrl.clear();
                          setState(() {
                            _searchQuery = '';
                          });
                          _filterApps();
                        },
                      ) : null,
                      filled: true,
                      fillColor: Colors.white.withOpacity(0.05),
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: BorderSide.none),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                InkWell(
                  onTap: () {
                    setState(() {
                      _hideSystemApps = !_hideSystemApps;
                    });
                    _filterApps();
                  },
                  child: Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: _hideSystemApps ? theme.colorScheme.primary.withOpacity(0.15) : Colors.white.withOpacity(0.05),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: _hideSystemApps ? theme.colorScheme.primary.withOpacity(0.4) : Colors.white.withOpacity(0.1),
                      ),
                    ),
                    child: Icon(
                      _hideSystemApps ? Icons.visibility_off_rounded : Icons.visibility_rounded,
                      color: _hideSystemApps ? theme.colorScheme.primary : Colors.white70,
                    ),
                  ),
                ),
              ],
            ),
          ),
          
          Expanded(
            child: _isLoading 
                ? const Center(child: CircularProgressIndicator())
                : _filteredApps.isEmpty
                    ? const Center(child: Text('No applications found', style: TextStyle(color: Colors.white54)))
                    : ListView.builder(
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        itemCount: _filteredApps.length,
                        itemBuilder: (context, index) {
                          final app = _filteredApps[index];
                          final pkg = app["package"] as String;
                          final name = app["name"] as String;
                          final isSystem = app["isSystem"] as bool;
                          final isSelected = _selectedPackages.contains(pkg);
                          final String? iconBase64 = app["icon"] as String?;
                          
                          final String initial = name.isNotEmpty ? name[0].toUpperCase() : '?';
                          final int colorHash = pkg.hashCode.abs();
                          final double hue = (colorHash % 360).toDouble();
                          
                          return Container(
                            margin: const EdgeInsets.only(bottom: 8),
                            decoration: BoxDecoration(
                              color: isSelected 
                                  ? (_routingMode == 'bypass' 
                                      ? theme.colorScheme.primary.withOpacity(0.08) 
                                      : theme.colorScheme.secondary.withOpacity(0.08))
                                  : Colors.white.withOpacity(0.02),
                              borderRadius: BorderRadius.circular(16),
                              border: Border.all(
                                color: isSelected 
                                  ? (_routingMode == 'bypass' 
                                      ? theme.colorScheme.primary.withOpacity(0.3) 
                                      : theme.colorScheme.secondary.withOpacity(0.3))
                                  : Colors.white.withOpacity(0.05),
                              ),
                            ),
                            child: ListTile(
                              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                              leading: iconBase64 != null && iconBase64.isNotEmpty
                                  ? ClipRRect(
                                      borderRadius: BorderRadius.circular(10),
                                      child: Image.memory(
                                        base64Decode(iconBase64),
                                        width: 40, height: 40,
                                        fit: BoxFit.cover,
                                        errorBuilder: (context, error, stackTrace) => Container(
                                          width: 40, height: 40,
                                          decoration: BoxDecoration(
                                            shape: BoxShape.circle,
                                            gradient: LinearGradient(
                                              colors: [
                                                HSVColor.fromAHSV(1.0, hue, 0.7, 0.8).toColor(),
                                                HSVColor.fromAHSV(1.0, (hue + 40) % 360, 0.8, 0.9).toColor(),
                                              ],
                                              begin: Alignment.topLeft,
                                              end: Alignment.bottomRight,
                                            ),
                                          ),
                                          child: Center(
                                            child: Text(
                                              initial,
                                              style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 16),
                                            ),
                                          ),
                                        ),
                                      ),
                                    )
                                  : Container(
                                      width: 40, height: 40,
                                      decoration: BoxDecoration(
                                        shape: BoxShape.circle,
                                        gradient: LinearGradient(
                                          colors: [
                                            HSVColor.fromAHSV(1.0, hue, 0.7, 0.8).toColor(),
                                            HSVColor.fromAHSV(1.0, (hue + 40) % 360, 0.8, 0.9).toColor(),
                                          ],
                                          begin: Alignment.topLeft,
                                          end: Alignment.bottomRight,
                                        ),
                                      ),
                                      child: Center(
                                        child: Text(
                                          initial,
                                          style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 16),
                                        ),
                                      ),
                                    ),
                              title: Row(
                                children: [
                                  Expanded(
                                    child: Text(
                                      name,
                                      style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15),
                                      maxLines: 1, overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                  if (isSystem) ...[
                                    const SizedBox(width: 8),
                                    Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                      decoration: BoxDecoration(
                                        color: Colors.white.withOpacity(0.1),
                                        borderRadius: BorderRadius.circular(4),
                                      ),
                                      child: const Text(
                                        'SYS',
                                        style: TextStyle(fontSize: 9, color: Colors.white60, fontWeight: FontWeight.bold),
                                      ),
                                    )
                                  ]
                                ],
                              ),
                              subtitle: Text(
                                pkg,
                                style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.white38),
                                maxLines: 1, overflow: TextOverflow.ellipsis,
                              ),
                              trailing: Switch(
                                value: isSelected,
                                activeColor: _routingMode == 'bypass' ? theme.colorScheme.primary : theme.colorScheme.secondary,
                                onChanged: (val) {
                                  setState(() {
                                    if (val) {
                                      _selectedPackages.add(pkg);
                                    } else {
                                      _selectedPackages.remove(pkg);
                                    }
                                  });
                                  _saveConfig();
                                },
                              ),
                            ),
                          );
                        },
                      ),
          ),
        ],
      ),
    );
  }
}


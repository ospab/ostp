import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../models/subscription.dart';

class QRScannerScreen extends StatefulWidget {
  const QRScannerScreen({super.key});

  @override
  State<QRScannerScreen> createState() => _QRScannerScreenState();
}

/// The ostp:// link or https:// subscription URL in a scanned code. Looks
/// in every field the scanner fills (some decoders put a URL only in `url`)
/// and anywhere in the text, not just at its start.
String? extractImportable(Barcode b) {
  final pattern = RegExp(r'(ostp://\S+|https://\S+)', caseSensitive: false);
  for (final text in [b.rawValue, b.displayValue, b.url?.url]) {
    if (text == null) continue;
    final m = pattern.firstMatch(text.trim());
    if (m != null) return m.group(1);
  }
  return null;
}

class _QRScannerScreenState extends State<QRScannerScreen> {
  static const _channel = MethodChannel('com.ospab.ostp/vpn');
  final MobileScannerController controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.normal,
    facing: CameraFacing.back,
  );

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  DateTime? lastErrorTime;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan QR Code'),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: Stack(
        alignment: Alignment.center,
        children: [
          MobileScanner(
            controller: controller,
            onDetect: (capture) {
              final List<Barcode> barcodes = capture.barcodes;
              for (final barcode in barcodes) {
                // A share link, or a subscription URL (https://<domain>/sub/<token>).
                final value = extractImportable(barcode);
                if (value != null && (value.toLowerCase().startsWith('ostp://') || isSubscriptionUrl(value))) {
                  controller.stop();
                  Navigator.pop(context, value);
                  return;
                }
                final now = DateTime.now();
                if (lastErrorTime == null || now.difference(lastErrorTime!) > const Duration(seconds: 3)) {
                  lastErrorTime = now;
                  final read = barcode.rawValue ?? barcode.displayValue ?? barcode.url?.url ?? '(no text)';
                  // Into the app log too, so a code that is not recognised can be traced.
                  _channel.invokeMethod('addLog', {'message': 'QR scanner: not importable (${barcode.format.name}): $read'}).catchError((_) => null);
                  final shown = read.length > 60 ? '${read.substring(0, 60)}…' : read;
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('Not an OSTP code. Read: $shown'),
                      backgroundColor: Colors.redAccent,
                      duration: const Duration(seconds: 3),
                    ),
                  );
                }
              }
            },
          ),
          Container(
            decoration: ShapeDecoration(
              shape: QrScannerOverlayShape(
                borderColor: Theme.of(context).colorScheme.primary,
                borderRadius: 10,
                borderLength: 30,
                borderWidth: 10,
                cutOutSize: 300,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class QrScannerOverlayShape extends ShapeBorder {
  final Color borderColor;
  final double borderWidth;
  final double borderRadius;
  final double borderLength;
  final double cutOutSize;

  const QrScannerOverlayShape({
    this.borderColor = Colors.red,
    this.borderWidth = 3.0,
    this.borderRadius = 0.0,
    this.borderLength = 20.0,
    this.cutOutSize = 250.0,
  });

  @override
  EdgeInsetsGeometry get dimensions => const EdgeInsets.all(10);

  @override
  Path getInnerPath(Rect rect, {TextDirection? textDirection}) {
    return Path()
      ..fillType = PathFillType.evenOdd
      ..addPath(getOuterPath(rect), Offset.zero);
  }

  @override
  Path getOuterPath(Rect rect, {TextDirection? textDirection}) {
    Path path = Path()..addRect(rect);
    rect = Rect.fromCenter(
      center: rect.center,
      width: cutOutSize,
      height: cutOutSize,
    );
    path.addRect(rect);
    return path;
  }

  @override
  void paint(Canvas canvas, Rect rect, {TextDirection? textDirection}) {
    final borderPaint = Paint()
      ..color = borderColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = borderWidth;
      
    final backgroundPaint = Paint()
      ..color = Colors.black54
      ..style = PaintingStyle.fill;

    final cutOutRect = Rect.fromCenter(
      center: rect.center,
      width: cutOutSize,
      height: cutOutSize,
    );

    final backgroundPath = Path()
      ..addRect(rect)
      ..addRect(cutOutRect)
      ..fillType = PathFillType.evenOdd;

    canvas.drawPath(backgroundPath, backgroundPaint);

    final path = Path();
    // Top left
    path.moveTo(cutOutRect.left, cutOutRect.top + borderLength);
    path.lineTo(cutOutRect.left, cutOutRect.top + borderRadius);
    path.arcToPoint(
      Offset(cutOutRect.left + borderRadius, cutOutRect.top),
      radius: Radius.circular(borderRadius),
    );
    path.lineTo(cutOutRect.left + borderLength, cutOutRect.top);

    // Top right
    path.moveTo(cutOutRect.right - borderLength, cutOutRect.top);
    path.lineTo(cutOutRect.right - borderRadius, cutOutRect.top);
    path.arcToPoint(
      Offset(cutOutRect.right, cutOutRect.top + borderRadius),
      radius: Radius.circular(borderRadius),
    );
    path.lineTo(cutOutRect.right, cutOutRect.top + borderLength);

    // Bottom left
    path.moveTo(cutOutRect.left, cutOutRect.bottom - borderLength);
    path.lineTo(cutOutRect.left, cutOutRect.bottom - borderRadius);
    path.arcToPoint(
      Offset(cutOutRect.left + borderRadius, cutOutRect.bottom),
      radius: Radius.circular(borderRadius),
      clockwise: false,
    );
    path.lineTo(cutOutRect.left + borderLength, cutOutRect.bottom);

    // Bottom right
    path.moveTo(cutOutRect.right - borderLength, cutOutRect.bottom);
    path.lineTo(cutOutRect.right - borderRadius, cutOutRect.bottom);
    path.arcToPoint(
      Offset(cutOutRect.right, cutOutRect.bottom - borderRadius),
      radius: Radius.circular(borderRadius),
      clockwise: false,
    );
    path.lineTo(cutOutRect.right, cutOutRect.bottom - borderLength);

    canvas.drawPath(path, borderPaint);
    
    // Line in the middle
    final linePaint = Paint()
      ..color = borderColor.withOpacity(0.8)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.0;
    
    canvas.drawLine(
      Offset(cutOutRect.left + 20, cutOutRect.center.dy),
      Offset(cutOutRect.right - 20, cutOutRect.center.dy),
      linePaint,
    );
  }

  @override
  ShapeBorder scale(double t) {
    return QrScannerOverlayShape(
      borderColor: borderColor,
      borderWidth: borderWidth * t,
      borderRadius: borderRadius * t,
      borderLength: borderLength * t,
      cutOutSize: cutOutSize * t,
    );
  }
}


import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';

import '../models/markdown.dart';

/// Shows the safe Markdown subset of [parseMarkdown] as widgets. Text is only
/// ever text: nothing is interpreted beyond that subset. [onLink] is called
/// with the URL of a tapped link.
class MarkdownView extends StatefulWidget {
  final String text;
  final void Function(String url) onLink;
  const MarkdownView({super.key, required this.text, required this.onLink});

  @override
  State<MarkdownView> createState() => _MarkdownViewState();
}

class _MarkdownViewState extends State<MarkdownView> {
  final _recognizers = <TapGestureRecognizer>[];
  List<Widget> _children = const [];

  @override
  void initState() {
    super.initState();
    _children = _build(parseMarkdown(widget.text));
  }

  @override
  void didUpdateWidget(MarkdownView old) {
    super.didUpdateWidget(old);
    if (old.text != widget.text) {
      _disposeRecognizers();
      _children = _build(parseMarkdown(widget.text));
    }
  }

  void _disposeRecognizers() {
    for (final r in _recognizers) {
      r.dispose();
    }
    _recognizers.clear();
  }

  @override
  void dispose() {
    _disposeRecognizers();
    super.dispose();
  }

  static const _mono = TextStyle(fontFamily: 'monospace', fontSize: 12.5, backgroundColor: Color(0x14FFFFFF));

  List<InlineSpan> _spans(List<MdInline> nodes) => [
        for (final n in nodes)
          if (n.kind == MdInlineKind.code)
            TextSpan(text: n.text, style: _mono)
          else
            TextSpan(
              text: n.text,
              style: TextStyle(
                fontWeight: n.bold ? FontWeight.w700 : null,
                fontStyle: n.italic ? FontStyle.italic : null,
                decoration: n.kind == MdInlineKind.link ? TextDecoration.underline : null,
              ),
              recognizer: n.kind == MdInlineKind.link ? _tap(n.url!) : null,
            ),
      ];

  TapGestureRecognizer _tap(String url) {
    final r = TapGestureRecognizer()..onTap = () => widget.onLink(url);
    _recognizers.add(r);
    return r;
  }

  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: _children);

  List<Widget> _build(List<MdBlock> blocks) {
    const base = TextStyle(fontSize: 14, height: 1.45, color: Colors.white);
    final children = <Widget>[];
    for (final b in blocks) {
      switch (b.kind) {
        case MdBlockKind.heading:
          children.add(Padding(
            padding: const EdgeInsets.only(top: 8, bottom: 4),
            child: Text.rich(TextSpan(children: _spans(b.inlines)),
                style: base.copyWith(fontWeight: FontWeight.w700, fontSize: const [17.0, 15.5, 14.5][b.level - 1])),
          ));
        case MdBlockKind.paragraph:
          children.add(Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Text.rich(TextSpan(children: _spans(b.inlines)), style: base),
          ));
        case MdBlockKind.code:
          children.add(Container(
            width: double.infinity,
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(8), border: Border.all(color: Colors.white12)),
            child: SelectableText(b.code, style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: Colors.white70)),
          ));
        case MdBlockKind.bullets:
        case MdBlockKind.numbered:
          for (var i = 0; i < b.items.length; i++) {
            children.add(Padding(
              padding: const EdgeInsets.only(bottom: 4, left: 4),
              child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                SizedBox(
                  width: 22,
                  child: Text(b.kind == MdBlockKind.bullets ? '•' : '${i + 1}.', style: base.copyWith(color: Colors.white54)),
                ),
                Expanded(child: Text.rich(TextSpan(children: _spans(b.items[i])), style: base)),
              ]),
            ));
          }
          if (b.items.isNotEmpty) children.add(const SizedBox(height: 4));
      }
    }
    return children;
  }
}

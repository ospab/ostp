/// A small, safe Markdown subset for text written by a server operator:
/// headings (#, ##, ###), paragraphs, **bold**, *italic*, `code`, fenced code
/// blocks, - / * / 1. lists and [links](url). Nothing else is interpreted:
/// HTML and every other construct stay visible as plain text. The same rules
/// as the desktop app (ostp-gui/src/markdown.js).
library;

const maxMarkdownChars = 8000;
const _maxUrl = 2048;

/// The link when it may be opened (http, https, mailto, tg), else null.
String? safeUrl(String url) {
  final u = url.trim();
  if (u.isEmpty || u.length > _maxUrl || RegExp(r'''[\s\x00-\x1f\x7f<>"']''').hasMatch(u)) return null;
  return RegExp(r'^(https?://[^/]|mailto:[^/]|tg:)', caseSensitive: false).hasMatch(u) ? u : null;
}

enum MdInlineKind { text, code, link }

class MdInline {
  final MdInlineKind kind;
  final String text;
  final String? url;
  final bool bold, italic;
  const MdInline(this.kind, this.text, {this.url, this.bold = false, this.italic = false});
}

enum MdBlockKind { heading, paragraph, code, bullets, numbered }

class MdBlock {
  final MdBlockKind kind;
  final int level; // headings: 1 to 3
  final List<MdInline> inlines; // headings and paragraphs
  final String code; // code blocks
  final List<List<MdInline>> items; // lists
  const MdBlock(this.kind, {this.level = 0, this.inlines = const [], this.code = '', this.items = const []});
}

final _escapable = RegExp(r'[\\`*_\[\]()#\-.!>]');

List<MdInline> parseInline(String s) {
  final out = <MdInline>[];
  final buf = StringBuffer();
  var b = false, it = false;
  void flush() {
    if (buf.isNotEmpty) {
      out.add(MdInline(MdInlineKind.text, buf.toString(), bold: b, italic: it));
      buf.clear();
    }
  }

  var i = 0;
  while (i < s.length) {
    final c = s[i];
    if (c == r'\' && i + 1 < s.length && _escapable.hasMatch(s[i + 1])) {
      buf.write(s[i + 1]);
      i += 2;
      continue;
    }
    if (c == '`') {
      final end = s.indexOf('`', i + 1);
      if (end > i + 1) {
        flush();
        out.add(MdInline(MdInlineKind.code, s.substring(i + 1, end)));
        i = end + 1;
        continue;
      }
    }
    if (c == '*' && i + 1 < s.length && s[i + 1] == '*') {
      // A marker opens only when it is closed later on the same text.
      if (b || s.indexOf('**', i + 2) > i + 2) {
        flush();
        b = !b;
      } else {
        buf.write('**');
      }
      i += 2;
      continue;
    }
    if (c == '*' && (it || (s.indexOf('*', i + 1) > i + 1 && s[i + 1] != ' '))) {
      flush();
      it = !it;
      i += 1;
      continue;
    }
    if (c == '[') {
      final close = s.indexOf('](', i + 1);
      final end = close > i ? s.indexOf(')', close + 2) : -1;
      if (close > i + 1 && end > close + 2 && !s.substring(i + 1, close).contains('[')) {
        final url = safeUrl(s.substring(close + 2, end));
        if (url != null) {
          flush();
          out.add(MdInline(MdInlineKind.link, s.substring(i + 1, close), url: url, bold: b, italic: it));
          i = end + 1;
          continue;
        }
      }
    }
    buf.write(c);
    i += 1;
  }
  flush();
  return out;
}

final _fence = RegExp(r'^\s*```');
final _heading = RegExp(r'^(#{1,3})\s+(.*)$');
final _bullet = RegExp(r'^\s{0,3}[-*]\s+(.*)$');
final _number = RegExp(r'^\s{0,3}\d{1,9}[.)]\s+(.*)$');
final _continued = RegExp(r'^\s+\S');

List<MdBlock> parseMarkdown(String src) {
  final text = src.length > maxMarkdownChars ? src.substring(0, maxMarkdownChars) : src;
  final lines = text.replaceAll('\r\n', '\n').replaceAll('\r', '\n').split('\n');
  final blocks = <MdBlock>[];
  final para = <String>[];
  MdBlockKind? listKind;
  final items = <String>[];
  void endPara() {
    if (para.isNotEmpty) {
      blocks.add(MdBlock(MdBlockKind.paragraph, inlines: parseInline(para.join(' '))));
      para.clear();
    }
  }

  void endList() {
    if (listKind != null) {
      blocks.add(MdBlock(listKind!, items: items.map(parseInline).toList()));
      listKind = null;
      items.clear();
    }
  }

  for (var n = 0; n < lines.length; n++) {
    final line = lines[n];
    if (_fence.hasMatch(line)) {
      endPara();
      endList();
      final code = <String>[];
      n += 1;
      while (n < lines.length && !_fence.hasMatch(lines[n])) {
        code.add(lines[n++]);
      }
      blocks.add(MdBlock(MdBlockKind.code, code: code.join('\n')));
      continue;
    }
    if (line.trim().isEmpty) {
      endPara();
      endList();
      continue;
    }
    final h = _heading.firstMatch(line);
    if (h != null) {
      endPara();
      endList();
      blocks.add(MdBlock(MdBlockKind.heading,
          level: h.group(1)!.length, inlines: parseInline(h.group(2)!.replaceFirst(RegExp(r'\s+#+\s*$'), ''))));
      continue;
    }
    final ul = _bullet.firstMatch(line);
    final ol = ul == null ? _number.firstMatch(line) : null;
    if (ul != null || ol != null) {
      endPara();
      final kind = ul != null ? MdBlockKind.bullets : MdBlockKind.numbered;
      if (listKind != null && listKind != kind) endList();
      listKind = kind;
      items.add((ul ?? ol)!.group(1)!);
      continue;
    }
    // An indented line right after a list item continues that item.
    if (listKind != null && _continued.hasMatch(line)) {
      items[items.length - 1] = '${items.last} ${line.trim()}';
      continue;
    }
    endList();
    para.add(line.trim());
  }
  endPara();
  endList();
  return blocks;
}

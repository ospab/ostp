# Panel design

Describes the current look of `index.html`. Keep to it; change it only on purpose.

## Colours (dark theme, the default)

- Background `#07080a`: page and login.
- Surface `#0e1013`: sidebar, dialogs, inputs.
- Card `#12151a`, border `#1f242c`: content blocks and dividers.
- Text `#eef1f4`, secondary text `#8b95a3`.
- Accent green `#2ee66d`: primary button, selected item, "on" and "connected".
- Status: red `#ff5f5f` (error, delete), amber `#f0b840` (warning, near limit), blue `#5aa9ff` (upload line, rewritten DNS answers).

The light theme (white surfaces, `#14a44d` accent) uses the same roles.

## Type

- System sans-serif stack (`-apple-system`, Segoe UI, Roboto), 14px body, 20px page title, 13-14px block headings in sentence case.
- System monospace for keys, addresses, domains and the JSON/config editors.
- No web fonts: the panel loads nothing from outside the server.

## Layout

A fixed left sidebar with the six pages (a top icon bar on phones) and one content column up to 1280px. Each page is a title row with its main actions, then blocks. Users become one block per user on a phone. Wide tables scroll inside their block.

## Principles

1. Show only what the server reports. No placeholder numbers; a value that cannot be loaded says so.
2. A button names its action. Anything destructive asks first and names what it affects. Every action ends in a toast or a note.
3. No decoration: no glows, gradients, grids, blur, entrance animation or hover movement. Colour carries state, not ornament.

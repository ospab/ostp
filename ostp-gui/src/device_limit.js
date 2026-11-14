// Subscriptions that limit devices: how the app reads the core's answer and
// what it does about it. Free of the page so it can be run with plain node.
//
// The core reports a refusal as the text "device:<code>:<server message>" where
// <code> is hwid_required or device_limit. Anything else is an ordinary error.

export const HWID_REQUIRED = 'hwid_required';
export const DEVICE_LIMIT = 'device_limit';

const PREFIX = 'device:';

// -> { kind: 'hwid_required' | 'device_limit' | 'other', message }
export function classifyFetchError(raw) {
  const text = String(raw ?? '');
  if (text.startsWith(PREFIX)) {
    const rest = text.slice(PREFIX.length);
    const i = rest.indexOf(':');
    const code = i < 0 ? rest : rest.slice(0, i);
    if (code === HWID_REQUIRED || code === DEVICE_LIMIT) {
      return { kind: code, message: (i < 0 ? '' : rest.slice(i + 1)).trim() };
    }
  }
  return { kind: 'other', message: text };
}

// The line on the subscription card (and in the toast) for a failed fetch.
export function cardMessage({ kind, message }) {
  if (kind === HWID_REQUIRED) return 'Device ID needed: turn on "Send a device ID to subscriptions" in settings';
  return message;
}

// A dialog is for a fetch the person started, never for a background refresh,
// and only when the answer is "send an ID" while sending is off. After the
// retry the dialog is not shown again.
export function shouldAskToSend({ kind, manual, sendOn, retried }) {
  return kind === HWID_REQUIRED && !!manual && !sendOn && !retried;
}

export const SEND_DIALOG = {
  title: 'This subscription limits devices',
  text: "The server needs this device's ID to count it. Send it?",
  ok: 'Send and retry',
};

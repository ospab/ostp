// Where the app's own requests (subscription refreshes, update checks, the update
// download) go. Free of the page so it can be run with plain node.
//
// The setting "Use the tunnel for subscriptions and updates" is on unless the person
// turned it off. The app core uses the tunnel only while it runs; with the tunnel down
// the request goes direct. A failure through the tunnel is an error, never a direct retry.

// Settings object -> true / false. Missing means on.
export function viaTunnelOn(settings) {
  return settings?.viaTunnel !== false;
}

// The arguments the commands fetch_subscription, check_updates and install_update take.
export function trafficArgs(settings) {
  return { viaTunnel: viaTunnelOn(settings), socks: String(settings?.socks ?? '').trim() || null };
}

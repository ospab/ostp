// ── OSTP GUI Internationalization ─────────────────────────────────────────────
// Supports: English (en), Russian (ru)

const translations = {
  en: {
    // Home screen
    status_disconnected: 'Disconnected',
    status_connecting: 'Connecting...',
    status_connected: 'Connected',
    hint_tap: 'Tap to protect your traffic',
    hint_connecting: 'Establishing secure tunnel...',
    hint_connected: 'Your traffic is encrypted',
    download: 'Download',
    upload: 'Upload',
    // Settings
    settings_title: 'Configuration',
    import_placeholder: 'Paste ostp:// share link here...',
    import_btn: 'Import',
    label_server: 'Server Address',
    label_key: 'Access Key',
    ph_key: 'Enter secure access key',
    label_socks: 'Local Proxy Address',
    label_dns: 'Custom DNS Server',
    label_owndns: 'Built-in Server DNS',
    owndns_hint: 'Route DNS queries through the VPN server (10.1.0.1)',
    label_tun: 'TUN Tunnel Mode',
    tun_hint: 'Route all system traffic (Admin req.)',
    label_kill_switch: 'Kill Switch',
    kill_switch_hint: 'Block non-VPN traffic when tunnel drops',
    label_transport: 'Transport Protocol',
    label_mtu: 'MTU Size',
    label_transport: 'Transport Protocol',
    label_sni: 'Stealth SNI (Fake Host)',
    label_pbk: 'Reality PublicKey (pbk)',
    label_sid: 'Reality ShortId (sid)',
    label_mtu: 'MTU Size',
    label_mux: 'Multiplexing (Mux)',
    mux_hint: 'Run multiple streams over one connection',
    label_mux_sessions: 'Mux Sessions',
    label_debug: 'Debug Logs',
    debug_hint: 'Enable verbose internal event outputs',
    excl_title: 'Exclusions',
    excl_hint: '(one per line)',
    excl_domains: 'Bypass Domains',
    excl_ips: 'Bypass IPs / CIDR Ranges',
    excl_processes: 'Bypass Processes',
    save_btn: 'Save & Apply',
    toast_saved: 'Configuration saved',
    toast_imported: 'Configuration imported',
    toast_error: 'Error',
    err_server_req: 'Server address is required',
    err_key_req: 'Access key is required',
    label_autoconnect: 'Auto-connect',
    autoconnect_hint: 'Connect automatically on startup',
    label_launch_startup: 'Launch at Startup',
    launch_startup_hint: 'Start OSTP with Windows',
    cancel_btn: 'Cancel',
    wintun_missing_title: 'Wintun Driver Missing',
    wintun_missing_desc: 'TUN mode requires the Wintun network driver (wintun.dll).',
    wintun_step1: 'Download wintun.zip from the official site',
    wintun_step2: 'Extract amd64\\wintun.dll from the archive',
    wintun_step3: 'Place it here:',
    wintun_step4: 'Restart the connection',
    wintun_open_btn: 'Open wintun.net ↗',
  },
  ru: {
    // Главный экран
    status_disconnected: 'Отключено',
    status_connecting: 'Подключение...',
    status_connected: 'Подключено',
    hint_tap: 'Нажмите для защиты трафика',
    hint_connecting: 'Установка защищённого туннеля...',
    hint_connected: 'Ваш трафик зашифрован',
    download: 'Входящий',
    upload: 'Исходящий',
    // Настройки
    settings_title: 'Настройки',
    import_placeholder: 'Вставьте ostp:// ссылку...',
    import_btn: 'Импорт',
    label_server: 'Адрес сервера',
    label_key: 'Ключ доступа',
    ph_key: 'Введите ключ доступа',
    label_socks: 'Адрес локального прокси',
    label_dns: 'DNS сервер',
    label_owndns: 'Встроенный DNS сервера',
    owndns_hint: 'Направлять DNS-запросы через VPN сервер (10.1.0.1)',
    label_tun: 'Режим TUN-туннеля',
    tun_hint: 'Направить весь трафик (нужны права администратора)',
    label_kill_switch: 'Kill Switch',
    kill_switch_hint: 'Блокировать трафик вне VPN при обрыве связи',
    label_transport: 'Транспортный протокол',
    label_mtu: 'Размер MTU',
    label_transport: 'Транспортный протокол',
    label_sni: 'Маскировочный SNI',
    label_pbk: 'Reality PublicKey (pbk)',
    label_sid: 'Reality ShortId (sid)',
    label_mtu: 'Размер MTU',
    label_mux: 'Мультиплексирование (Mux)',
    mux_hint: 'Несколько потоков через одно соединение',
    label_mux_sessions: 'Сессий Mux',
    label_debug: 'Журнал отладки',
    debug_hint: 'Включить подробный вывод событий',
    excl_title: 'Исключения',
    excl_hint: '(по одному на строку)',
    excl_domains: 'Обход для доменов',
    excl_ips: 'Обход для IP / CIDR',
    excl_processes: 'Обход для процессов',
    save_btn: 'Сохранить',
    toast_saved: 'Настройки сохранены',
    toast_imported: 'Настройки импортированы',
    toast_error: 'Ошибка',
    err_server_req: 'Укажите адрес сервера',
    err_key_req: 'Укажите ключ доступа',
    label_autoconnect: 'Автоподключение',
    autoconnect_hint: 'Подключаться автоматически при запуске',
    label_launch_startup: 'Запуск вместе с Windows',
    launch_startup_hint: 'Автозапуск OSTP при входе в систему',
    cancel_btn: 'Отмена',
    wintun_missing_title: 'Отсутствует драйвер Wintun',
    wintun_missing_desc: 'Режим TUN требует сетевой драйвер Wintun (wintun.dll).',
    wintun_step1: 'Скачайте wintun.zip с официального сайта',
    wintun_step2: 'Извлеките amd64\\wintun.dll из архива',
    wintun_step3: 'Поместите файл сюда:',
    wintun_step4: 'Перезапустите подключение',
    wintun_open_btn: 'Открыть wintun.net ↗',
  },
};

let currentLang = localStorage.getItem('ostp_lang') || 'en';

export function t(key) {
  const dict = translations[currentLang] || translations.en;
  return dict[key] || translations.en[key] || key;
}

export function getLang() {
  return currentLang;
}

export function setLang(lang) {
  if (!translations[lang]) return;
  currentLang = lang;
  localStorage.setItem('ostp_lang', lang);
  applyTranslations();
}

export function toggleLang() {
  const next = currentLang === 'en' ? 'ru' : 'en';
  setLang(next);
  return next;
}

export function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const value = t(key);
    if (value) el.textContent = value;
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    const value = t(key);
    if (value) el.placeholder = value;
  });
  const langLabel = document.getElementById('lang-label');
  if (langLabel) langLabel.textContent = currentLang.toUpperCase();
}

import { useState, useEffect } from 'react';
import { BookOpen, RefreshCw, AlertTriangle, ExternalLink } from 'lucide-react';
import { useLanguage } from '../lib/LanguageContext';

const CONFIG_GUIDE_URL = 'https://raw.githubusercontent.com/ospab/ostp/master/ostp-wiki/configuration_guide.md';
const API_ENDPOINTS_URL = 'https://raw.githubusercontent.com/ospab/ostp/master/ostp-wiki/api_endpoints.md';

export default function Wiki() {
  const { t } = useLanguage();
  const [activeTab, setActiveTab] = useState<'config' | 'api'>('config');
  const [markdown, setMarkdown] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchDoc = async (tab: 'config' | 'api') => {
    setIsLoading(true);
    setErrorMsg(null);
    const targetUrl = tab === 'config' ? CONFIG_GUIDE_URL : API_ENDPOINTS_URL;

    try {
      const response = await fetch(targetUrl);
      if (!response.ok) throw new Error(`HTTP status ${response.status}`);
      const text = await response.text();
      setMarkdown(text);
    } catch (err: any) {
      console.warn("Failed to fetch markdown from GitHub, using offline backup copy", err);
      setErrorMsg(t('wk_load_error'));
      // Load local offline backup copies
      setMarkdown(tab === 'config' ? LOCAL_CONFIG_GUIDE_BACKUP : LOCAL_API_ENDPOINTS_BACKUP);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDoc(activeTab);
  }, [activeTab]);

  return (
    <div className="relative z-10 w-full max-w-5xl mx-auto space-y-6 animate-in fade-in duration-300">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1 flex items-center gap-3">
            <BookOpen className="w-8 h-8 text-primary" /> {t('wk_title')}
          </h1>
          <p className="text-text-muted">{t('wk_subtitle')}</p>
        </div>
        <a 
          href="https://github.com/ospab/ostp/wiki" 
          target="_blank" 
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-xs text-primary hover:underline font-semibold bg-primary/10 border border-primary/20 px-3.5 py-2 rounded-xl shrink-0"
        >
          GitHub Wiki <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-white/5 gap-2">
        <button
          onClick={() => setActiveTab('config')}
          disabled={isLoading}
          className={`px-5 py-3 font-medium transition-colors border-b-2 text-sm ${
            activeTab === 'config' ? 'border-primary text-white' : 'border-transparent text-text-muted hover:text-white'
          }`}
        >
          {t('wk_tab_guide')}
        </button>
        <button
          onClick={() => setActiveTab('api')}
          disabled={isLoading}
          className={`px-5 py-3 font-medium transition-colors border-b-2 text-sm ${
            activeTab === 'api' ? 'border-primary text-white' : 'border-transparent text-text-muted hover:text-white'
          }`}
        >
          {t('wk_tab_api')}
        </button>
      </div>

      {/* Error alert */}
      {errorMsg && (
        <div className="bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 p-4 rounded-xl flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
          <p className="text-xs font-semibold font-mono leading-relaxed">{errorMsg}</p>
        </div>
      )}

      {/* Loading state */}
      {isLoading ? (
        <div className="glass-panel rounded-2xl p-16 flex flex-col items-center justify-center text-center gap-3">
          <RefreshCw className="w-8 h-8 animate-spin text-primary" />
          <span className="text-sm text-text-muted font-medium">{t('wk_loading')}</span>
        </div>
      ) : (
        <div className="glass-panel rounded-2xl p-8 shadow-xl border border-white/10 prose prose-invert max-w-none prose-sm">
          {renderMarkdown(markdown)}
        </div>
      )}
    </div>
  );
}

// Custom Markdown Renderer to JSX/HTML
function renderMarkdown(md: string) {
  const lines = md.split('\n');
  const elements: React.ReactNode[] = [];
  let inCodeBlock = false;
  let codeBlockContent: string[] = [];
  
  let inTable = false;
  let tableHeaders: string[] = [];
  let tableRows: string[][] = [];

  const parseInline = (text: string) => {
    const regex = /(\*\*.*?\*\*|`.*?`)/g;
    const segments = text.split(regex);
    
    return segments.map((seg, idx) => {
      if (seg.startsWith('**') && seg.endsWith('**')) {
        return <strong key={idx} className="text-white font-bold">{seg.slice(2, -2)}</strong>;
      }
      if (seg.startsWith('`') && seg.endsWith('`')) {
        return <code key={idx} className="bg-white/10 px-1.5 py-0.5 rounded font-mono text-xs text-primary">{seg.slice(1, -1)}</code>;
      }
      return seg;
    });
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Code block
    if (line.startsWith('```')) {
      if (inCodeBlock) {
        inCodeBlock = false;
        elements.push(
          <pre key={i} className="bg-black/50 border border-white/15 p-4 rounded-xl font-mono text-xs overflow-x-auto text-secondary/90 my-4 select-all">
            <code>{codeBlockContent.join('\n')}</code>
          </pre>
        );
        codeBlockContent = [];
      } else {
        inCodeBlock = true;
      }
      continue;
    }

    if (inCodeBlock) {
      codeBlockContent.push(lines[i]);
      continue;
    }

    // Tables
    if (line.startsWith('|')) {
      inTable = true;
      const cells = line.split('|').map(c => c.trim()).filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
      
      if (cells.every(c => c.startsWith('-'))) {
        continue;
      }
      
      if (tableHeaders.length === 0) {
        tableHeaders = cells;
      } else {
        tableRows.push(cells);
      }
      continue;
    } else if (inTable) {
      // Table ended, compile it
      elements.push(
        <div key={`table-${i}`} className="overflow-x-auto my-4 border border-white/5 rounded-xl">
          <table className="w-full text-left border-collapse bg-white/[0.01]">
            <thead>
              <tr className="border-b border-white/5 bg-white/[0.02]">
                {tableHeaders.map((h, idx) => (
                  <th key={idx} className="px-4 py-3 font-semibold text-text-muted text-xs uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-sm">
              {tableRows.map((row, rIdx) => (
                <tr key={rIdx} className="hover:bg-white/[0.01]">
                  {row.map((cell, cIdx) => (
                    <td key={cIdx} className="px-4 py-2.5 text-white/90 font-medium">{parseInline(cell)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      inTable = false;
      tableHeaders = [];
      tableRows = [];
    }

    if (line === '') {
      continue;
    }

    // Headers
    if (line.startsWith('# ')) {
      elements.push(<h1 key={i} className="text-2xl font-extrabold text-white mt-6 mb-3 border-b border-white/5 pb-2">{parseInline(line.slice(2))}</h1>);
    } else if (line.startsWith('## ')) {
      elements.push(<h2 key={i} className="text-xl font-bold text-white mt-5 mb-3">{parseInline(line.slice(3))}</h2>);
    } else if (line.startsWith('### ')) {
      elements.push(<h3 key={i} className="text-lg font-semibold text-white mt-4 mb-2">{parseInline(line.slice(4))}</h3>);
    }
    // Lists
    else if (line.startsWith('- ') || line.startsWith('* ')) {
      elements.push(
        <ul key={i} className="list-disc list-inside ml-4 text-sm text-text-muted my-1.5">
          <li>{parseInline(line.slice(2))}</li>
        </ul>
      );
    }
    // Horizontal rule
    else if (line === '---') {
      elements.push(<hr key={i} className="border-t border-white/5 my-6" />);
    }
    // Paragraph
    else {
      elements.push(<p key={i} className="text-sm text-text-muted leading-relaxed my-2">{parseInline(line)}</p>);
    }
  }

  // Handle unclosed table at the end
  if (inTable) {
    elements.push(
      <div key={`table-end`} className="overflow-x-auto my-4 border border-white/5 rounded-xl">
        <table className="w-full text-left border-collapse bg-white/[0.01]">
          <thead>
            <tr className="border-b border-white/5 bg-white/[0.02]">
              {tableHeaders.map((h, idx) => (
                <th key={idx} className="px-4 py-3 font-semibold text-text-muted text-xs uppercase">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-sm">
            {tableRows.map((row, rIdx) => (
              <tr key={rIdx} className="hover:bg-white/[0.01]">
                {row.map((cell, cIdx) => (
                  <td key={cIdx} className="px-4 py-2.5 text-white/90 font-medium">{parseInline(cell)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return elements;
}

const LOCAL_CONFIG_GUIDE_BACKUP = `# Руководство по конфигурации OSTP (\`config.json\`)

Файл \`config.json\` является основным конфигурационным файлом для сервера, клиента и реле.

## Полный пример конфигурации

\`\`\`json
{
  "mode": "server",
  "log_level": "info",
  "listen": "0.0.0.0:50000",
  "access_keys": [
    "some_simple_key",
    {
      "access_key": "detailed_key_with_limit",
      "name": "Рабочий Ноутбук",
      "limit_bytes": 107374182400
    }
  ],
  "api": {
    "enabled": true,
    "bind": "127.0.0.1:9090",
    "token": "7a3f8b2c4d9e0f1a2b3c4d5e6f7a8b9c"
  },
  "fallback": {
    "enabled": false,
    "listen": "0.0.0.0:443",
    "target": "127.0.0.1:8080"
  },
  "reality": {
    "enabled": false,
    "dest": "www.microsoft.com:443",
    "private_key": "...",
    "pbk": "...",
    "sid": "...",
    "sni_list": ["www.microsoft.com"]
  },
  "outbound": {
    "enabled": false,
    "protocol": "socks5",
    "address": "127.0.0.1",
    "port": 9050,
    "default_action": "proxy"
  },
  "debug": false
}
\`\`\`

## Описание разделов конфигурации

### 1. Основные параметры
- **\`mode\`** (строка): Режим работы. Варианты: \`"server"\`, \`"client"\`, \`"relay"\`.
- **\`log_level\`** (строка): Уровень логирования. Варианты: \`"debug"\`, \`"info"\`, \`"warn"\`, \`"error"\`.
- **\`listen\`** (строка или массив строк): Интерфейс и порт входящих соединений. Пример: \`"0.0.0.0:50000"\`.
- **\`debug\`** (логический): Подробная сетевая отладка протокола.

### 2. Ключи доступа (\`access_keys\`)
Раздел содержит массив ключей доступа. Поддерживается два формата записи:
1. **Простая строка**: Текст ключа доступа. Лимит трафика отсутствует.
2. **Объект с метаданными**:
   - \`access_key\` (строка, обязательно): Текст ключа для подключения.
   - \`name\` (строка, опционально): Описание клиента.
   - \`limit_bytes\` (число, опционально): Лимит трафика в байтах.

### 3. REST API Управления (\`api\`)
Используется для интеграции с панелью управления \`ostp-control\`.
- **\`enabled\`** (логический): Включение веб-сервера API.
- **\`bind\`** (строка): Адрес прослушивания (например, \`"127.0.0.1:9090"\`).
- **\`token\`** (строка): Bearer-токен для авторизации администратора.

### 4. Встроенный TCP Fallback прокси (\`fallback\`)
- **\`enabled\`** (логический): Включить проксирование TCP.
- **\`listen\`** (строка): Порт прослушивания TCP/TLS (например, \`"0.0.0.0:443"\`).
- **\`target\`** (строка): Локальный веб-сервер (например, \`"127.0.0.1:8080"\` на nginx/caddy), куда пересылаются все обычные запросы.

### 5. Reality Маскировка (\`reality\`)
Реализует маскировку Reality (XTLS).
- **\`enabled\`** (логический): Включение Reality.
- **\`dest\`** (строка): Домен назначения (например, \`"www.microsoft.com:443"\`).
- **\`private_key\`** (строка): Приватный ключ X25519.
- **\`pbk\`** (строка): Публичный ключ X25519.
- **\`sid\`** (строка, 8 байт hex): Идентификатор сессии.
- **\`sni_list\`** (массив строк): Разрешенные SNI заголовки от клиентов.`;

const LOCAL_API_ENDPOINTS_BACKUP = `# Справочник API управления OSTP

Сервер OSTP предоставляет REST API для управления пользователями и просмотра статистики.

## Авторизация
Все запросы должны содержать заголовок \`Authorization\` с API-токеном:
\`\`\`http
Authorization: Bearer <ваш_api_токен>
\`\`\`

## Список эндпоинтов

### 1. Статус сервера
- **URL**: \`/api/server/status\`
- **Метод**: \`GET\`
- **Формат data**:
\`\`\`json
{
  "version": "0.2.30",
  "uptime_seconds": 12053,
  "active_users": 2,
  "total_users": 5
}
\`\`\`

### 2. Получение текущего конфига
- **URL**: \`/api/server/config\`
- **Метод**: \`GET\`
- **Формат data**: Полный JSON-конфиг сервера.

### 3. Обновление конфига
- **URL**: \`/api/server/config\`
- **Метод**: \`PUT\`
- **Тело запроса**: JSON нового конфигурационного файла. Вызывает hot-reload ядра.

### 4. Список клиентов и их статистика
- **URL**: \`/api/users\`
- **Метод**: \`GET\`
- **Формат data**:
\`\`\`json
[
  {
    "access_key": "ostp_key_sample1",
    "bytes_up": 2405020,
    "bytes_down": 491029402,
    "connections": 2,
    "limit_bytes": 10737418240,
    "online": true,
    "name": "Ноутбук"
  }
]
\`\`\`

### 5. Создание клиента
- **URL**: \`/api/users\`
- **Метод**: \`POST\`
- **Тело запроса**:
\`\`\`json
{
  "access_key": "my_custom_key_optional",
  "name": "Имя клиента",
  "limit_bytes": 50000000000
}
\`\`\`

### 6. Удаление клиента
- **URL**: \`/api/users/:key\`
- **Метод**: \`DELETE\`

### 7. Обновление клиента
- **URL**: \`/api/users/:key\`
- **Метод**: \`PUT\`
- **Тело запроса**: \`{"name": "...", "limit_bytes": ...}\`

### 8. Сброс счетчиков трафика
- **URL**: \`/api/users/{key}/reset\`
- **Метод**: \`POST\``;

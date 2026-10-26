// The PPPoE & PPP page - full suite for PPP services and subscribers.
//
// Tabs:
// - secrets: configured PPP subscriber credentials (/ppp/secret)
// - active: live connected sessions (/ppp/active)
// - inactive: secrets without an active session
// - interfaces: dynamic PPPoE server interfaces (/interface/pppoe-server)
// - servers: PPPoE service instances (/interface/pppoe-server/server)
// - profiles: PPP user profiles (/ppp/profile)

import {
  esc,
  el,
  resRow,
  debounce,
  renderSortHeader,
  sortMul,
  fmtMbps,
  fmtBytes,
  parseUptime,
  pill,
  type SortCol,
  type SortState,
  mutedDash,
} from '../dom';
import type { Socket } from '../socket';
import { mountAdds, mountRows } from '../resource';
import type { PPPSession, PPPSecret, PPPProfile, PPPServer, PPPoEInterface, PPPPayload } from '../gen/payloads';

const PPP_TAB_RES: Record<string, string> = {
  secrets: 'pppSecret',
  active: '',
  inactive: 'pppSecret',
  interfaces: '',
  servers: '',
  profiles: 'pppProfile',
};

const COLS_SECRET: SortCol[] = [
  { key: 'state', label: 'State' },
  { key: 'name', label: 'User' },
  { key: 'service', label: 'Service' },
  { key: 'profile', label: 'Profile' },
  { key: 'localAddress', label: 'Local' },
  { key: 'remoteAddress', label: 'Remote' },
  { key: 'callerId', label: 'Caller ID' },
  { key: 'comment', label: 'Comment' },
];

const COLS_ACTIVE: SortCol[] = [
  { key: 'name', label: 'User' },
  { key: 'service', label: 'Service' },
  { key: 'address', label: 'Address' },
  { key: 'callerId', label: 'Caller ID' },
  { key: 'uptime', label: 'Uptime' },
  { key: 'rate', label: 'RX / TX' },
  { key: 'total', label: 'Total In / Out' },
];

const COLS_INTERFACES: SortCol[] = [
  { key: 'name', label: 'Interface' },
  { key: 'user', label: 'User' },
  { key: 'interface', label: 'Base Interface' },
  { key: 'uptime', label: 'Uptime' },
  { key: 'state', label: 'State' },
];

const COLS_SERVERS: SortCol[] = [
  { key: 'serviceName', label: 'Service Name' },
  { key: 'interface', label: 'Interface' },
  { key: 'maxSessions', label: 'Max Sessions' },
  { key: 'auth', label: 'Authentication' },
  { key: 'state', label: 'State' },
];

const COLS_PROFILES: SortCol[] = [
  { key: 'name', label: 'Profile Name' },
  { key: 'localAddress', label: 'Local Address' },
  { key: 'remoteAddress', label: 'Remote Address' },
  { key: 'rateLimit', label: 'Rate Limit' },
  { key: 'onlyOne', label: 'Only One' },
  { key: 'encryption', label: 'Encryption' },
];

export function initPppPage(socket: Socket, isVisible: (page: string) => boolean): void {
  const card = el('pppCard') || el('pppSecretTable');
  if (!card) return;

  let data: PPPPayload | null = null;
  let activeTab = 'secrets';

  const sortSecrets: SortState = { col: 'name', dir: 'asc' };
  const sortActive: SortState = { col: 'name', dir: 'asc' };
  const sortInactive: SortState = { col: 'name', dir: 'asc' };
  const sortInterfaces: SortState = { col: 'name', dir: 'asc' };
  const sortServers: SortState = { col: 'serviceName', dir: 'asc' };
  const sortProfiles: SortState = { col: 'name', dir: 'asc' };

  function secretSortVal(s: PPPSecret, key: string): string | number {
    if (key === 'state') return s.disabled ? 2 : s.connected ? 0 : 1;
    return String((s as unknown as Record<string, unknown>)[key] || '').toLowerCase();
  }

  function activeSortVal(s: PPPSession, key: string): string | number {
    if (key === 'rate') return (s.rxRate || 0) + (s.txRate || 0);
    if (key === 'total') return s.rx + s.tx;
    if (key === 'uptime') return parseUptime(s.uptime);
    return String((s as unknown as Record<string, unknown>)[key] || '').toLowerCase();
  }

  function renderSecrets(): void {
    const tb = el('pppSecretTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('pppSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const all = data.secrets || [];

    const rows = all.filter((s) => {
      if (!q) return true;
      return (s.name + ' ' + (s.profile || '') + ' ' + (s.localAddress || '') + ' ' +
        (s.remoteAddress || '') + ' ' + (s.callerId || '') + ' ' + (s.comment || '')).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const av = secretSortVal(a, sortSecrets.col);
      const bv = secretSortVal(b, sortSecrets.col);
      if (typeof av === 'string') return sortMul(sortSecrets) * av.localeCompare(bv as string);
      return sortMul(sortSecrets) * ((av as number) - (bv as number));
    });

    renderSortHeader('pppSecretThead', COLS_SECRET, sortSecrets, () => renderSecrets());

    const badge = el('pppSecretBadge');
    if (badge) {
      badge.textContent = String(all.length);
      badge.className = 'card-badge' + (all.length ? ' active-blue' : '');
    }

    const empty = data.available
      ? 'No PPP secrets. Add one to let a subscriber connect.'
      : 'This router has no PPP service configured.';

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((s) => {
      const state = s.disabled
        ? pill('disabled', 'warn')
        : s.connected
          ? pill('online', 'ok')
          : pill('offline', 'muted');
      return '<tr' + (s.disabled ? ' style="opacity:.55"' : '') + resRow(s.id, s.name) + '>' +
        '<td>' + state + '</td>' +
        '<td>' + esc(s.name) + '</td>' +
        '<td>' + pill(s.service || 'any', 'rx') + '</td>' +
        cell(s.profile) + cell(s.localAddress) + cell(s.remoteAddress) + cell(s.callerId) + cell(s.comment) +
      '</tr>';
    }).join('') : '<tr><td colspan="8" class="empty-state">' + esc(q ? 'No secrets match that search.' : empty) + '</td></tr>';
  }

  function renderActive(): void {
    const tb = el('pppTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('pppSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const all = data.sessions || [];

    const rows = all.filter((s) => {
      if (!q) return true;
      return (s.name + ' ' + s.address + ' ' + s.callerId + ' ' + s.service).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const av = activeSortVal(a, sortActive.col);
      const bv = activeSortVal(b, sortActive.col);
      if (typeof av === 'string') return sortMul(sortActive) * av.localeCompare(bv as string);
      return sortMul(sortActive) * ((av as number) - (bv as number));
    });

    renderSortHeader('pppThead', COLS_ACTIVE, sortActive, () => renderActive());

    const badge = el('pppActiveBadge') || el('pppBadge');
    if (badge) {
      badge.textContent = String(all.length);
      badge.className = 'card-badge' + (all.length ? ' active-blue' : '');
    }

    const empty = data.available
      ? 'No active PPP sessions. They appear here when a PPPoE, L2TP, SSTP or PPTP client connects.'
      : 'This router has no PPP service configured.';

    tb.innerHTML = rows.length ? rows.map((s) => {
      const r = s.rxRate === null
        ? '<span style="color:var(--text-muted)">-</span>'
        : '<span style="color:var(--accent-rx)">' + fmtMbps((s.rxRate * 8) / 1e6) + '</span> / ' +
          '<span style="color:var(--accent-tx)">' + fmtMbps(((s.txRate as number) * 8) / 1e6) + '</span>';
      return '<tr' + resRow(s.id, s.name) + '>' +
        '<td>' + esc(s.name) + '</td>' +
        '<td>' + pill(s.service || 'PPP', 'rx') + '</td>' +
        '<td>' + esc(s.address) + '</td>' +
        '<td>' + esc(s.callerId) + '</td>' +
        '<td>' + esc(s.uptime) + '</td>' +
        '<td>' + r + '</td>' +
        '<td>' + fmtBytes(s.rx) + ' / ' + fmtBytes(s.tx) + '</td>' +
      '</tr>';
    }).join('') : '<tr><td colspan="7" class="empty-state">' + esc(empty) + '</td></tr>';
  }

  function renderInactive(): void {
    const tb = el('pppInactiveTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('pppSearch');
    const q = (search?.value || '').toLowerCase().trim();
    // Inactive: secrets where connected === false
    const inactive = (data.secrets || []).filter((s) => !s.connected);

    const rows = inactive.filter((s) => {
      if (!q) return true;
      return (s.name + ' ' + (s.profile || '') + ' ' + (s.localAddress || '') + ' ' +
        (s.remoteAddress || '') + ' ' + (s.callerId || '') + ' ' + (s.comment || '')).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const av = secretSortVal(a, sortInactive.col);
      const bv = secretSortVal(b, sortInactive.col);
      if (typeof av === 'string') return sortMul(sortInactive) * av.localeCompare(bv as string);
      return sortMul(sortInactive) * ((av as number) - (bv as number));
    });

    renderSortHeader('pppInactiveThead', COLS_SECRET, sortInactive, () => renderInactive());

    const badge = el('pppInactiveBadge');
    if (badge) {
      badge.textContent = String(inactive.length);
      badge.className = 'card-badge' + (inactive.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((s) => {
      const state = s.disabled ? pill('disabled', 'warn') : pill('offline', 'muted');
      return '<tr' + (s.disabled ? ' style="opacity:.55"' : '') + resRow(s.id, s.name) + '>' +
        '<td>' + state + '</td>' +
        '<td>' + esc(s.name) + '</td>' +
        '<td>' + pill(s.service || 'any', 'rx') + '</td>' +
        cell(s.profile) + cell(s.localAddress) + cell(s.remoteAddress) + cell(s.callerId) + cell(s.comment) +
      '</tr>';
    }).join('') : '<tr><td colspan="8" class="empty-state">' + esc(q ? 'No inactive secrets match search.' : 'No inactive secrets.') + '</td></tr>';
  }

  function renderInterfaces(): void {
    const tb = el('pppInterfacesTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('pppSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const ifaces = data.interfaces || [];

    const rows = ifaces.filter((iface) => {
      if (!q) return true;
      return (iface.name + ' ' + iface.user + ' ' + iface.interface).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortInterfaces.col as keyof PPPoEInterface;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortInterfaces) * av.localeCompare(bv);
    });

    renderSortHeader('pppInterfacesThead', COLS_INTERFACES, sortInterfaces, () => renderInterfaces());

    const badge = el('pppInterfacesBadge');
    if (badge) {
      badge.textContent = String(ifaces.length);
      badge.className = 'card-badge' + (ifaces.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((iface) => {
      const state = iface.disabled
        ? pill('disabled', 'warn')
        : iface.running
          ? pill('running', 'ok')
          : pill('inactive', 'muted');
      return '<tr>' +
        '<td>' + esc(iface.name) + '</td>' +
        '<td>' + esc(iface.user) + '</td>' +
        cell(iface.interface) +
        cell(iface.uptime) +
        '<td>' + state + '</td>' +
      '</tr>';
    }).join('') : '<tr><td colspan="5" class="empty-state">No active PPPoE server interfaces.</td></tr>';
  }

  function renderServers(): void {
    const tb = el('pppServerTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('pppSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const servers = data.servers || [];

    const rows = servers.filter((s) => {
      if (!q) return true;
      return (s.serviceName + ' ' + s.interface + ' ' + s.auth).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortServers.col as keyof PPPServer;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortServers) * av.localeCompare(bv);
    });

    renderSortHeader('pppServersThead', COLS_SERVERS, sortServers, () => renderServers());

    const badge = el('pppServerBadge');
    if (badge) {
      badge.textContent = String(servers.length);
      badge.className = 'card-badge' + (servers.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((s) =>
      '<tr' + (s.disabled ? ' style="opacity:.55"' : '') + resRow(s.id, s.serviceName || '(unnamed)') + '>' +
        '<td>' + esc(s.serviceName || '(unnamed)') + '</td>' +
        cell(s.interface) +
        cell(s.maxSessions ? String(s.maxSessions) : 'unlimited') +
        cell(s.auth) +
        '<td>' + (s.disabled ? pill('disabled', 'warn') : pill('enabled', 'ok')) + '</td>' +
      '</tr>').join('')
      : '<tr><td colspan="5" class="empty-state">No PPPoE servers configured.</td></tr>';
  }

  function renderProfiles(): void {
    const tb = el('pppProfileTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('pppSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const profiles = data.profiles || [];

    const rows = profiles.filter((p) => {
      if (!q) return true;
      return (p.name + ' ' + p.localAddress + ' ' + p.remoteAddress + ' ' + p.rateLimit).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortProfiles.col as keyof PPPProfile;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortProfiles) * av.localeCompare(bv);
    });

    renderSortHeader('pppProfilesThead', COLS_PROFILES, sortProfiles, () => renderProfiles());

    const badge = el('pppProfileBadge');
    if (badge) {
      badge.textContent = String(profiles.length);
      badge.className = 'card-badge' + (profiles.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((p) =>
      '<tr' + resRow(p.id, p.name) + '>' +
        '<td>' + esc(p.name) + '</td>' +
        cell(p.localAddress) +
        cell(p.remoteAddress) +
        cell(p.rateLimit) +
        cell(p.onlyOne) +
        cell(p.encryption) +
      '</tr>').join('')
      : '<tr><td colspan="6" class="empty-state">No PPP profiles.</td></tr>';
  }

  function renderSummary(): void {
    if (!data) return;
    const activeCount = data.sessions?.length || 0;
    const secretsCount = data.secrets?.length || 0;
    const inactiveCount = (data.secrets || []).filter((s) => !s.connected).length;

    const countEl = el('pppSumCount');
    if (countEl) countEl.textContent = String(activeCount);

    const inactiveEl = el('pppSumInactive');
    if (inactiveEl) inactiveEl.textContent = String(inactiveCount);

    const secretsEl = el('pppSumSecrets');
    if (secretsEl) secretsEl.textContent = String(secretsCount);

    const badge = el('pppBadge');
    if (badge) {
      badge.textContent = String(activeCount);
      badge.className = 'card-badge' + (activeCount ? ' active-blue' : '');
    }

    const toMbps = (v: number | null): number | null => (v === null ? null : (v * 8) / 1e6);
    const rx = toMbps(data.totalRxRate);
    const tx = toMbps(data.totalTxRate);
    const rxEl = el('pppSumRx');
    const txEl = el('pppSumTx');
    if (rxEl) rxEl.innerHTML = rx === null ? '-' : fmtMbps(rx);
    if (txEl) txEl.innerHTML = tx === null ? '-' : fmtMbps(tx);
  }

  function renderCurrentTab(): void {
    if (!data) return;
    switch (activeTab) {
      case 'secrets':
        renderSecrets();
        break;
      case 'active':
        renderActive();
        break;
      case 'inactive':
        renderInactive();
        break;
      case 'interfaces':
        renderInterfaces();
        break;
      case 'servers':
        renderServers();
        break;
      case 'profiles':
        renderProfiles();
        break;
    }
  }

  function renderAll(): void {
    if (!data) return;
    renderSummary();
    renderSecrets();
    renderActive();
    renderInactive();
    renderInterfaces();
    renderServers();
    renderProfiles();
  }

  function syncAddSlot(): void {
    const slot = el('pppAddSlot');
    if (!slot) return;
    slot.setAttribute('data-res-add', PPP_TAB_RES[activeTab] || '');
    document.dispatchEvent(new CustomEvent('mikrodash:resmount'));
  }

  function setPppTab(t: string): void {
    if (!(t in PPP_TAB_RES)) return;
    activeTab = t;
    document.querySelectorAll<HTMLElement>('[data-ppptab]').forEach((b) => {
      const on = b.dataset.ppptab === t;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    Object.keys(PPP_TAB_RES).forEach((k) => {
      const panel = el('ppptab-' + k);
      if (panel) panel.hidden = k !== t;
    });
    syncAddSlot();
    renderCurrentTab();
  }

  el('pppCfgTabBar')?.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement | null)?.closest?.('[data-ppptab]') as HTMLElement | null;
    if (btn) setPppTab(btn.dataset.ppptab || '');
  });

  const searchInput = el<HTMLInputElement>('pppSearch');
  searchInput?.addEventListener('input', debounce(renderCurrentTab, 150));

  socket.on('ppp:update', (d) => {
    if (!d) return;
    data = d;
    renderSummary();
    if (isVisible('ppp')) renderAll();
  });

  document.addEventListener('mikrodash:pagechange', (e) => {
    if ((e as CustomEvent).detail === 'ppp' && data) renderAll();
  });

  mountAdds(socket);
  mountRows(socket);
}

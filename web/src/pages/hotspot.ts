// The HotSpot page - full management for MikroTik Captive Portal.
//
// Tabs:
// - users: configured HotSpot users (/ip/hotspot/user)
// - active: live active sessions (/ip/hotspot/active)
// - inactive: users not currently in active sessions
// - userProfiles: HotSpot user profiles (/ip/hotspot/user/profile)
// - servers: HotSpot server instances (/ip/hotspot)
// - serverProfiles: HotSpot server profiles (/ip/hotspot/profile)
// - hosts: connected DHCP/ARP hotspot hosts (/ip/hotspot/host)
// - ipBinding: static IP/MAC bypass and bindings (/ip/hotspot/ip-binding)
// - walledGarden: allowed URLs and IPs before authentication
// - cookies: active browser login cookies (/ip/hotspot/cookie)

import {
  esc,
  el,
  resRow,
  debounce,
  renderSortHeader,
  sortMul,
  fmtMbps,
  fmtBytes,
  pill,
  type SortCol,
  type SortState,
  mutedDash,
} from '../dom';
import type { Socket } from '../socket';
import { mountAdds, mountRows } from '../resource';
import type {
  HotspotPayload,
  HotspotUser,
  HotspotActiveSession,
  HotspotUserProfile,
  HotspotServer,
  HotspotServerProfile,
  HotspotHost,
  HotspotIPBinding,
  HotspotWalledGarden,
  HotspotCookie,
} from '../gen/payloads';

const HOTSPOT_TAB_RES: Record<string, string> = {
  users: 'hotspotUser',
  active: '',
  inactive: 'hotspotUser',
  userProfiles: 'hotspotUserProfile',
  servers: 'hotspotServer',
  serverProfiles: 'hotspotServerProfile',
  hosts: '',
  ipBinding: 'hotspotIPBinding',
  walledGarden: 'hotspotWalledGarden',
  cookies: '',
};

const COLS_USERS: SortCol[] = [
  { key: 'state', label: 'State' },
  { key: 'name', label: 'Username' },
  { key: 'profile', label: 'Profile' },
  { key: 'server', label: 'Server' },
  { key: 'limitUptime', label: 'Limit Uptime' },
  { key: 'bytes', label: 'Limit Bytes' },
  { key: 'comment', label: 'Comment' },
];

const COLS_ACTIVE: SortCol[] = [
  { key: 'user', label: 'User' },
  { key: 'server', label: 'Server' },
  { key: 'address', label: 'Address' },
  { key: 'macAddress', label: 'MAC Address' },
  { key: 'loginBy', label: 'Login By' },
  { key: 'uptime', label: 'Uptime' },
  { key: 'rate', label: 'RX / TX' },
  { key: 'total', label: 'Total In / Out' },
];

const COLS_USER_PROFILES: SortCol[] = [
  { key: 'name', label: 'Profile Name' },
  { key: 'sharedUsers', label: 'Shared Users' },
  { key: 'rateLimit', label: 'Rate Limit' },
  { key: 'idleTimeout', label: 'Idle Timeout' },
  { key: 'keepaliveTimeout', label: 'Keepalive' },
  { key: 'addressPool', label: 'Address Pool' },
];

const COLS_SERVERS: SortCol[] = [
  { key: 'name', label: 'Server Name' },
  { key: 'interface', label: 'Interface' },
  { key: 'addressPool', label: 'Address Pool' },
  { key: 'profile', label: 'Profile' },
  { key: 'idleTimeout', label: 'Idle Timeout' },
  { key: 'state', label: 'State' },
];

const COLS_SERVER_PROFILES: SortCol[] = [
  { key: 'name', label: 'Profile Name' },
  { key: 'hotspotAddress', label: 'Hotspot Address' },
  { key: 'htmlDirectory', label: 'HTML Directory' },
  { key: 'rateLimit', label: 'Rate Limit' },
  { key: 'loginBy', label: 'Login By' },
  { key: 'dnsName', label: 'DNS Name' },
];

const COLS_HOSTS: SortCol[] = [
  { key: 'macAddress', label: 'MAC Address' },
  { key: 'address', label: 'Address' },
  { key: 'toAddress', label: 'To Address' },
  { key: 'server', label: 'Server' },
  { key: 'state', label: 'State' },
  { key: 'idleTime', label: 'Idle Time' },
  { key: 'bytes', label: 'Bytes In / Out' },
];

const COLS_IP_BINDING: SortCol[] = [
  { key: 'macAddress', label: 'MAC Address' },
  { key: 'address', label: 'Address' },
  { key: 'toAddress', label: 'To Address' },
  { key: 'server', label: 'Server' },
  { key: 'type', label: 'Type' },
  { key: 'comment', label: 'Comment' },
  { key: 'state', label: 'State' },
];

const COLS_WALLED_GARDEN: SortCol[] = [
  { key: 'action', label: 'Action' },
  { key: 'server', label: 'Server' },
  { key: 'dst', label: 'Dst Host / Address' },
  { key: 'dstPort', label: 'Dst Port' },
  { key: 'path', label: 'Path' },
  { key: 'comment', label: 'Comment' },
  { key: 'state', label: 'State' },
];

const COLS_COOKIES: SortCol[] = [
  { key: 'user', label: 'User' },
  { key: 'macAddress', label: 'MAC Address' },
  { key: 'domain', label: 'Domain' },
  { key: 'expiresIn', label: 'Expires In' },
];

export function initHotspotPage(socket: Socket, isVisible: (page: string) => boolean): void {
  const card = el('hotspotCard');
  if (!card) return;

  let data: HotspotPayload | null = null;
  let activeTab = 'users';

  const sortUsers: SortState = { col: 'name', dir: 'asc' };
  const sortActive: SortState = { col: 'user', dir: 'asc' };
  const sortInactive: SortState = { col: 'name', dir: 'asc' };
  const sortUserProfiles: SortState = { col: 'name', dir: 'asc' };
  const sortServers: SortState = { col: 'name', dir: 'asc' };
  const sortServerProfiles: SortState = { col: 'name', dir: 'asc' };
  const sortHosts: SortState = { col: 'macAddress', dir: 'asc' };
  const sortIPBinding: SortState = { col: 'macAddress', dir: 'asc' };
  const sortWalledGarden: SortState = { col: 'action', dir: 'asc' };
  const sortCookies: SortState = { col: 'user', dir: 'asc' };

  function userSortVal(u: HotspotUser, key: string): string | number {
    if (key === 'state') return u.disabled ? 2 : u.connected ? 0 : 1;
    if (key === 'bytes') return (u.limitBytesTotal || 0);
    return String((u as unknown as Record<string, unknown>)[key] || '').toLowerCase();
  }

  function activeSortVal(a: HotspotActiveSession, key: string): string | number {
    if (key === 'rate') return (a.rxRate || 0) + (a.txRate || 0);
    if (key === 'total') return (a.bytesIn || 0) + (a.bytesOut || 0);
    return String((a as unknown as Record<string, unknown>)[key] || '').toLowerCase();
  }

  function renderUsers(): void {
    const tb = el('hsUsersTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const all = data.users || [];

    const rows = all.filter((u) => {
      if (!q) return true;
      return (u.name + ' ' + u.profile + ' ' + u.server + ' ' + u.comment).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const av = userSortVal(a, sortUsers.col);
      const bv = userSortVal(b, sortUsers.col);
      if (typeof av === 'string') return sortMul(sortUsers) * av.localeCompare(bv as string);
      return sortMul(sortUsers) * ((av as number) - (bv as number));
    });

    renderSortHeader('hsUsersThead', COLS_USERS, sortUsers, () => renderUsers());

    const badge = el('hsUsersBadge');
    if (badge) {
      badge.textContent = String(all.length);
      badge.className = 'card-badge' + (all.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((u) => {
      const state = u.disabled
        ? pill('disabled', 'warn')
        : u.connected
          ? pill('active', 'ok')
          : pill('inactive', 'muted');
      const bytesStr = u.limitBytesTotal
        ? fmtBytes(u.limitBytesTotal)
        : dash;
      return '<tr' + (u.disabled ? ' style="opacity:.55"' : '') + resRow(u.id, u.name) + '>' +
        '<td>' + state + '</td>' +
        '<td>' + esc(u.name) + '</td>' +
        cell(u.profile) +
        cell(u.server || 'all') +
        cell(u.limitUptime) +
        '<td>' + bytesStr + '</td>' +
        cell(u.comment) +
      '</tr>';
    }).join('') : '<tr><td colspan="7" class="empty-state">No HotSpot users configured.</td></tr>';
  }

  function renderActive(): void {
    const tb = el('hsActiveTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const all = data.active || [];

    const rows = all.filter((a) => {
      if (!q) return true;
      return (a.user + ' ' + a.server + ' ' + a.address + ' ' + a.macAddress + ' ' + a.loginBy).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const av = activeSortVal(a, sortActive.col);
      const bv = activeSortVal(b, sortActive.col);
      if (typeof av === 'string') return sortMul(sortActive) * av.localeCompare(bv as string);
      return sortMul(sortActive) * ((av as number) - (bv as number));
    });

    renderSortHeader('hsActiveThead', COLS_ACTIVE, sortActive, () => renderActive());

    const badge = el('hsActiveBadge');
    if (badge) {
      badge.textContent = String(all.length);
      badge.className = 'card-badge' + (all.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((a) => {
      const r = a.rxRate === null
        ? '<span style="color:var(--text-muted)">-</span>'
        : '<span style="color:var(--accent-rx)">' + fmtMbps((a.rxRate * 8) / 1e6) + '</span> / ' +
          '<span style="color:var(--accent-tx)">' + fmtMbps(((a.txRate as number) * 8) / 1e6) + '</span>';
      return '<tr' + resRow(a.id, a.user) + '>' +
        '<td>' + esc(a.user) + '</td>' +
        cell(a.server) +
        cell(a.address) +
        cell(a.macAddress) +
        '<td>' + pill(a.loginBy || 'login', 'rx') + '</td>' +
        cell(a.uptime) +
        '<td>' + r + '</td>' +
        '<td>' + fmtBytes(a.bytesIn) + ' / ' + fmtBytes(a.bytesOut) + '</td>' +
      '</tr>';
    }).join('') : '<tr><td colspan="8" class="empty-state">No active HotSpot sessions.</td></tr>';
  }

  function renderInactive(): void {
    const tb = el('hsInactiveTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    // Inactive: HotSpot users where connected === false
    const inactive = (data.users || []).filter((u) => !u.connected);

    const rows = inactive.filter((u) => {
      if (!q) return true;
      return (u.name + ' ' + u.profile + ' ' + u.server + ' ' + u.comment).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const av = userSortVal(a, sortInactive.col);
      const bv = userSortVal(b, sortInactive.col);
      if (typeof av === 'string') return sortMul(sortInactive) * av.localeCompare(bv as string);
      return sortMul(sortInactive) * ((av as number) - (bv as number));
    });

    renderSortHeader('hsInactiveThead', COLS_USERS, sortInactive, () => renderInactive());

    const badge = el('hsInactiveBadge');
    if (badge) {
      badge.textContent = String(inactive.length);
      badge.className = 'card-badge' + (inactive.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((u) => {
      const state = u.disabled ? pill('disabled', 'warn') : pill('inactive', 'muted');
      const bytesStr = u.limitBytesTotal
        ? fmtBytes(u.limitBytesTotal)
        : dash;
      return '<tr' + (u.disabled ? ' style="opacity:.55"' : '') + resRow(u.id, u.name) + '>' +
        '<td>' + state + '</td>' +
        '<td>' + esc(u.name) + '</td>' +
        cell(u.profile) +
        cell(u.server || 'all') +
        cell(u.limitUptime) +
        '<td>' + bytesStr + '</td>' +
        cell(u.comment) +
      '</tr>';
    }).join('') : '<tr><td colspan="7" class="empty-state">No inactive HotSpot users.</td></tr>';
  }

  function renderUserProfiles(): void {
    const tb = el('hsUserProfilesTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const profiles = data.userProfiles || [];

    const rows = profiles.filter((p) => {
      if (!q) return true;
      return (p.name + ' ' + p.rateLimit + ' ' + p.addressPool).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortUserProfiles.col as keyof HotspotUserProfile;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortUserProfiles) * av.localeCompare(bv);
    });

    renderSortHeader('hsUserProfilesThead', COLS_USER_PROFILES, sortUserProfiles, () => renderUserProfiles());

    const badge = el('hsUserProfilesBadge');
    if (badge) {
      badge.textContent = String(profiles.length);
      badge.className = 'card-badge' + (profiles.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((p) =>
      '<tr' + resRow(p.id, p.name) + '>' +
        '<td>' + esc(p.name) + '</td>' +
        cell(p.sharedUsers ? String(p.sharedUsers) : '1') +
        cell(p.rateLimit) +
        cell(p.idleTimeout) +
        cell(p.keepaliveTimeout) +
        cell(p.addressPool) +
      '</tr>').join('')
      : '<tr><td colspan="6" class="empty-state">No HotSpot user profiles configured.</td></tr>';
  }

  function renderServers(): void {
    const tb = el('hsServersTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const servers = data.servers || [];

    const rows = servers.filter((s) => {
      if (!q) return true;
      return (s.name + ' ' + s.interface + ' ' + s.profile + ' ' + s.addressPool).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortServers.col as keyof HotspotServer;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortServers) * av.localeCompare(bv);
    });

    renderSortHeader('hsServersThead', COLS_SERVERS, sortServers, () => renderServers());

    const badge = el('hsServersBadge');
    if (badge) {
      badge.textContent = String(servers.length);
      badge.className = 'card-badge' + (servers.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((s) =>
      '<tr' + (s.disabled ? ' style="opacity:.55"' : '') + resRow(s.id, s.name) + '>' +
        '<td>' + esc(s.name) + '</td>' +
        cell(s.interface) +
        cell(s.addressPool) +
        cell(s.profile) +
        cell(s.idleTimeout) +
        '<td>' + (s.disabled ? pill('disabled', 'warn') : pill('enabled', 'ok')) + '</td>' +
      '</tr>').join('')
      : '<tr><td colspan="6" class="empty-state">No HotSpot servers configured.</td></tr>';
  }

  function renderServerProfiles(): void {
    const tb = el('hsServerProfilesTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const profiles = data.serverProfiles || [];

    const rows = profiles.filter((p) => {
      if (!q) return true;
      return (p.name + ' ' + p.hotspotAddress + ' ' + p.htmlDirectory + ' ' + p.loginBy).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortServerProfiles.col as keyof HotspotServerProfile;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortServerProfiles) * av.localeCompare(bv);
    });

    renderSortHeader('hsServerProfilesThead', COLS_SERVER_PROFILES, sortServerProfiles, () => renderServerProfiles());

    const badge = el('hsServerProfilesBadge');
    if (badge) {
      badge.textContent = String(profiles.length);
      badge.className = 'card-badge' + (profiles.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((p) =>
      '<tr' + resRow(p.id, p.name) + '>' +
        '<td>' + esc(p.name) + '</td>' +
        cell(p.hotspotAddress) +
        cell(p.htmlDirectory) +
        cell(p.rateLimit) +
        cell(p.loginBy) +
        cell(p.dnsName) +
      '</tr>').join('')
      : '<tr><td colspan="6" class="empty-state">No HotSpot server profiles configured.</td></tr>';
  }

  function renderHosts(): void {
    const tb = el('hsHostsTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const hosts = data.hosts || [];

    const rows = hosts.filter((h) => {
      if (!q) return true;
      return (h.macAddress + ' ' + h.address + ' ' + h.toAddress + ' ' + h.server).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortHosts.col as keyof HotspotHost;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortHosts) * av.localeCompare(bv);
    });

    renderSortHeader('hsHostsThead', COLS_HOSTS, sortHosts, () => renderHosts());

    const badge = el('hsHostsBadge');
    if (badge) {
      badge.textContent = String(hosts.length);
      badge.className = 'card-badge' + (hosts.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((h) => {
      const state = h.bypassed
        ? pill('bypassed', 'alt')
        : h.authorized
          ? pill('authorized', 'ok')
          : pill('unauthorized', 'muted');
      return '<tr' + resRow(h.id, h.macAddress) + '>' +
        '<td>' + esc(h.macAddress) + '</td>' +
        cell(h.address) +
        cell(h.toAddress) +
        cell(h.server) +
        '<td>' + state + '</td>' +
        cell(h.idleTime) +
        '<td>' + fmtBytes(h.bytesIn) + ' / ' + fmtBytes(h.bytesOut) + '</td>' +
      '</tr>';
    }).join('') : '<tr><td colspan="7" class="empty-state">No HotSpot hosts detected.</td></tr>';
  }

  function renderIPBinding(): void {
    const tb = el('hsIPBindingTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const bindings = data.ipBindings || [];

    const rows = bindings.filter((b) => {
      if (!q) return true;
      return (b.macAddress + ' ' + b.address + ' ' + b.toAddress + ' ' + b.server + ' ' + b.comment).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortIPBinding.col as keyof HotspotIPBinding;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortIPBinding) * av.localeCompare(bv);
    });

    renderSortHeader('hsIPBindingThead', COLS_IP_BINDING, sortIPBinding, () => renderIPBinding());

    const badge = el('hsIPBindingBadge');
    if (badge) {
      badge.textContent = String(bindings.length);
      badge.className = 'card-badge' + (bindings.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((b) => {
      const typeKind = b.type === 'bypassed' ? 'ok' : b.type === 'blocked' ? 'warn' : 'rx';
      return '<tr' + (b.disabled ? ' style="opacity:.55"' : '') + resRow(b.id, b.macAddress || b.address) + '>' +
        cell(b.macAddress) +
        cell(b.address) +
        cell(b.toAddress) +
        cell(b.server || 'all') +
        '<td>' + pill(b.type || 'regular', typeKind) + '</td>' +
        cell(b.comment) +
        '<td>' + (b.disabled ? pill('disabled', 'warn') : pill('enabled', 'ok')) + '</td>' +
      '</tr>';
    }).join('') : '<tr><td colspan="7" class="empty-state">No IP bindings configured.</td></tr>';
  }

  function renderWalledGarden(): void {
    const tb = el('hsWalledGardenTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const wg = data.walledGarden || [];

    const rows = wg.filter((w) => {
      if (!q) return true;
      return (w.server + ' ' + w.dstHost + ' ' + w.path + ' ' + w.comment).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortWalledGarden.col as keyof HotspotWalledGarden;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortWalledGarden) * av.localeCompare(bv);
    });

    renderSortHeader('hsWalledGardenThead', COLS_WALLED_GARDEN, sortWalledGarden, () => renderWalledGarden());

    const badge = el('hsWalledGardenBadge');
    if (badge) {
      badge.textContent = String(wg.length);
      badge.className = 'card-badge' + (wg.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((w) => {
      const actKind = w.action === 'allow' ? 'ok' : 'warn';
      return '<tr' + (w.disabled ? ' style="opacity:.55"' : '') + resRow(w.id, w.dstHost || w.server || '(all)') + '>' +
        '<td>' + pill(w.action || 'allow', actKind) + '</td>' +
        cell(w.server || 'all') +
        cell(w.dstHost) +
        cell(w.dstPort) +
        cell(w.path) +
        cell(w.comment) +
        '<td>' + (w.disabled ? pill('disabled', 'warn') : pill('enabled', 'ok')) + '</td>' +
      '</tr>';
    }).join('') : '<tr><td colspan="7" class="empty-state">No Walled Garden entries.</td></tr>';
  }

  function renderCookies(): void {
    const tb = el('hsCookiesTable');
    if (!tb || !data) return;
    const search = el<HTMLInputElement>('hsSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const cookies = data.cookies || [];

    const rows = cookies.filter((c) => {
      if (!q) return true;
      return (c.user + ' ' + c.macAddress + ' ' + c.domain).toLowerCase().indexOf(q) !== -1;
    }).slice().sort((a, b) => {
      const k = sortCookies.col as keyof HotspotCookie;
      const av = String(a[k] || '').toLowerCase();
      const bv = String(b[k] || '').toLowerCase();
      return sortMul(sortCookies) * av.localeCompare(bv);
    });

    renderSortHeader('hsCookiesThead', COLS_COOKIES, sortCookies, () => renderCookies());

    const badge = el('hsCookiesBadge');
    if (badge) {
      badge.textContent = String(cookies.length);
      badge.className = 'card-badge' + (cookies.length ? ' active-blue' : '');
    }

    const dash = mutedDash();
    const cell = (v: string): string => '<td>' + (v ? esc(v) : dash) + '</td>';

    tb.innerHTML = rows.length ? rows.map((c) =>
      '<tr' + resRow(c.id, c.user) + '>' +
        '<td>' + esc(c.user) + '</td>' +
        cell(c.macAddress) +
        cell(c.domain) +
        cell(c.expiresIn) +
      '</tr>').join('')
      : '<tr><td colspan="4" class="empty-state">No active HotSpot cookies.</td></tr>';
  }

  function renderSummary(): void {
    if (!data) return;
    const activeCount = data.active?.length || 0;
    const usersCount = data.users?.length || 0;
    const inactiveCount = (data.users || []).filter((u) => !u.connected).length;
    const hostsCount = data.hosts?.length || 0;

    const activeEl = el('hsSumActive');
    if (activeEl) activeEl.textContent = String(activeCount);

    const usersEl = el('hsSumUsers');
    if (usersEl) usersEl.textContent = String(usersCount);

    const inactiveEl = el('hsSumInactive');
    if (inactiveEl) inactiveEl.textContent = String(inactiveCount);

    const hostsEl = el('hsSumHosts');
    if (hostsEl) hostsEl.textContent = String(hostsCount);

    const badge = el('hsBadge');
    if (badge) {
      badge.textContent = String(activeCount);
      badge.className = 'card-badge' + (activeCount ? ' active-blue' : '');
    }

    const toMbps = (v: number | null): number | null => (v === null ? null : (v * 8) / 1e6);
    const rx = toMbps(data.totalRxRate);
    const tx = toMbps(data.totalTxRate);
    const rxEl = el('hsSumRx');
    const txEl = el('hsSumTx');
    if (rxEl) rxEl.innerHTML = rx === null ? '-' : fmtMbps(rx);
    if (txEl) txEl.innerHTML = tx === null ? '-' : fmtMbps(tx);
  }

  function renderCurrentTab(): void {
    if (!data) return;
    switch (activeTab) {
      case 'users':
        renderUsers();
        break;
      case 'active':
        renderActive();
        break;
      case 'inactive':
        renderInactive();
        break;
      case 'userProfiles':
        renderUserProfiles();
        break;
      case 'servers':
        renderServers();
        break;
      case 'serverProfiles':
        renderServerProfiles();
        break;
      case 'hosts':
        renderHosts();
        break;
      case 'ipBinding':
        renderIPBinding();
        break;
      case 'walledGarden':
        renderWalledGarden();
        break;
      case 'cookies':
        renderCookies();
        break;
    }
  }

  function renderAll(): void {
    if (!data) return;
    renderSummary();
    renderUsers();
    renderActive();
    renderInactive();
    renderUserProfiles();
    renderServers();
    renderServerProfiles();
    renderHosts();
    renderIPBinding();
    renderWalledGarden();
    renderCookies();
  }

  function syncAddSlot(): void {
    const slot = el('hsAddSlot');
    if (!slot) return;
    slot.setAttribute('data-res-add', HOTSPOT_TAB_RES[activeTab] || '');
    document.dispatchEvent(new CustomEvent('mikrodash:resmount'));
  }

  function setHsTab(t: string): void {
    if (!(t in HOTSPOT_TAB_RES)) return;
    activeTab = t;
    document.querySelectorAll<HTMLElement>('[data-hstab]').forEach((b) => {
      const on = b.dataset.hstab === t;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    Object.keys(HOTSPOT_TAB_RES).forEach((k) => {
      const panel = el('hstab-' + k);
      if (panel) panel.hidden = k !== t;
    });
    syncAddSlot();
    renderCurrentTab();
  }

  el('hsTabBar')?.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement | null)?.closest?.('[data-hstab]') as HTMLElement | null;
    if (btn) setHsTab(btn.dataset.hstab || '');
  });

  const searchInput = el<HTMLInputElement>('hsSearch');
  searchInput?.addEventListener('input', debounce(renderCurrentTab, 150));

  socket.on('hotspot:update', (d) => {
    if (!d) return;
    data = d;
    renderSummary();
    if (isVisible('hotspot')) renderAll();
  });

  document.addEventListener('mikrodash:pagechange', (e) => {
    if ((e as CustomEvent).detail === 'hotspot' && data) renderAll();
  });

  mountAdds(socket);
  mountRows(socket);
}

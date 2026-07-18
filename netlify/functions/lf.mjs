import { getStore } from '@netlify/blobs';
import crypto from 'crypto';

const GROUPS = () => getStore('lf-groups');
const TOKENS = () => getStore('lf-tokens');
const RATE = () => getStore('lf-ratelimit');
const SETTINGS = () => getStore('lf-settings');

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 6; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

function genToken() {
  return crypto.randomBytes(24).toString('hex');
}

function hashPass(pass, salt) {
  return crypto.scryptSync(pass, salt, 64).toString('hex');
}

async function getGroup(code) {
  return await GROUPS().get(code.toUpperCase(), { type: 'json' });
}
async function saveGroup(g) {
  await GROUPS().setJSON(g.code, g);
}
async function getTokenRecord(tok) {
  if (!tok) return null;
  return await TOKENS().get(tok, { type: 'json' });
}
async function saveTokenRecord(tok, rec) {
  await TOKENS().setJSON(tok, rec);
}
function bearer(req) {
  const h = req.headers.get('authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : null;
}
function clientIp(req) {
  return req.headers.get('x-nf-client-connection-ip')
    || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim()
    || 'unknown';
}

// Simple sliding-window rate limit backed by blobs. Returns true if allowed.
async function allow(req, bucket, limit, windowMs) {
  const ip = clientIp(req);
  const key = bucket + ':' + ip;
  const store = RATE();
  const now = Date.now();
  let rec = await store.get(key, { type: 'json' });
  if (!rec || (now - rec.start) > windowMs) rec = { count: 0, start: now };
  rec.count++;
  await store.setJSON(key, rec);
  return rec.count <= limit;
}

async function getSettings() {
  const s = await SETTINGS().get('global', { type: 'json' });
  return s || { paywallEnabled: false };
}
async function saveSettings(s) {
  await SETTINGS().setJSON('global', s);
}

function isAdmin(req) {
  const key = req.headers.get('x-admin-key') || '';
  const expected = process.env.ADMIN_KEY || '';
  if (!expected || !key || key.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(key), Buffer.from(expected));
  } catch (e) {
    return false;
  }
}

export default async (req) => {
  try {
    const url = new URL(req.url);
    let path = url.pathname.replace(/^\/api\/lf/, '');
    if (!path) path = '/';
    const method = req.method;
    const parts = path.split('/').filter(Boolean);
    let body = {};
    if (method !== 'GET' && method !== 'HEAD') {
      try { body = await req.json(); } catch (e) {}
    }

    if (method === 'POST' && parts[0] === 'groups' && parts.length === 1) {
      if (!(await allow(req, 'create-group', 10, 10 * 60 * 1000))) {
        return json(429, { error: 'Too many attempts. Please wait a few minutes and try again.' });
      }
      const hodName = (body.hodName || '').trim();
      const passphrase = body.passphrase || '';
      if (!hodName) return json(400, { error: 'Name is required.' });
      if (!passphrase || passphrase.length < 6) return json(400, { error: 'Passphrase must be at least 6 characters.' });

      let code;
      for (let i = 0; i < 8; i++) {
        code = genCode();
        if (!(await getGroup(code))) break;
      }
      const salt = crypto.randomBytes(16).toString('hex');
      const group = {
        code, hodName,
        passphraseSalt: salt,
        passphraseHash: hashPass(passphrase, salt),
        teachers: {},
        sow: { data: null, updatedAt: null },
        createdAt: Date.now()
      };
      await saveGroup(group);
      const token = genToken();
      await saveTokenRecord(token, { code, tid: 'hod', role: 'hod', name: hodName });
      return json(201, { token, code });
    }

    if (method === 'POST' && parts[0] === 'groups' && parts[2] === 'login' && parts.length === 3) {
      if (!(await allow(req, 'hod-login', 15, 10 * 60 * 1000))) {
        return json(429, { error: 'Too many attempts. Please wait a few minutes and try again.' });
      }
      const code = parts[1].toUpperCase();
      const group = await getGroup(code);
      if (!group) return json(404, { error: 'Join code not found.' });
      const passphrase = body.passphrase || '';
      if (!passphrase) return json(400, { error: 'Passphrase is required.' });
      const check = hashPass(passphrase, group.passphraseSalt);
      if (check !== group.passphraseHash) return json(401, { error: 'Incorrect passphrase.' });
      const token = genToken();
      await saveTokenRecord(token, { code, tid: 'hod', role: 'hod', name: group.hodName });
      return json(200, { token, code, hodName: group.hodName });
    }

    if (method === 'POST' && parts[0] === 'groups' && parts[2] === 'teachers' && parts.length === 3) {
      if (!(await allow(req, 'join-teacher', 60, 10 * 60 * 1000))) {
        return json(429, { error: 'Too many attempts. Please wait a few minutes and try again.' });
      }
      const code = parts[1].toUpperCase();
      const group = await getGroup(code);
      if (!group) return json(404, { error: 'Join code not found. Check with your HoD.' });
      const name = (body.name || '').trim();
      if (!name) return json(400, { error: 'Name is required.' });
      const avatarColor = body.avatarColor || '#7c63f8';

      // Idempotent rejoin: if a teacher with this name already exists, restore
      // them (and their existing progress) instead of creating a duplicate.
      const existing = Object.values(group.teachers).find(
        t => t.name.trim().toLowerCase() === name.toLowerCase()
      );
      let tid, finalAvatarColor;
      if (existing) {
        tid = existing.id;
        existing.avatarColor = avatarColor || existing.avatarColor;
        existing.updatedAt = Date.now();
        finalAvatarColor = existing.avatarColor;
      } else {
        tid = crypto.randomBytes(6).toString('hex');
        group.teachers[tid] = { id: tid, name, avatarColor, progress: {}, notes: {}, preferences: {}, updatedAt: Date.now() };
        finalAvatarColor = avatarColor;
      }
      await saveGroup(group);
      const token = genToken();
      await saveTokenRecord(token, { code, tid, role: 'teacher', name });
      return json(201, { token, teacher: { id: tid, name, avatarColor: finalAvatarColor } });
    }

    if (method === 'GET' && parts[0] === 'billing' && parts[1] === 'status') {
      const settings = await getSettings();
      return json(200, { active: !settings.paywallEnabled });
    }
    if (method === 'GET' && parts[0] === 'billing' && parts[1] === 'plans') {
      return json(200, []);
    }
    if (method === 'POST' && parts[0] === 'billing' && parts[1] === 'checkout') {
      return json(400, { error: 'Billing is not set up yet, your account is free for now.' });
    }

    // ── Admin routes (protected by x-admin-key header) ──
    if (parts[0] === 'admin') {
      if (!(await allow(req, 'admin', 60, 10 * 60 * 1000))) {
        return json(429, { error: 'Too many attempts. Please wait a few minutes and try again.' });
      }
      if (!isAdmin(req)) return json(401, { error: 'Invalid admin key.' });

      if (method === 'GET' && parts[1] === 'stats' && parts.length === 2) {
        const { blobs } = await GROUPS().list();
        const groups = [];
        for (const b of blobs) {
          const key = b.key || b;
          const g = await getGroup(key);
          if (!g) continue;
          const teachers = Object.values(g.teachers || {});
          const activityTimes = [
            g.createdAt || 0,
            (g.sow && g.sow.updatedAt) || 0,
            ...teachers.map(t => t.updatedAt || 0)
          ];
          groups.push({
            code: g.code,
            hodName: g.hodName,
            teacherCount: teachers.length,
            createdAt: g.createdAt,
            lastActivity: Math.max(...activityTimes)
          });
        }
        groups.sort((a, b) => (b.lastActivity || 0) - (a.lastActivity || 0));
        const totalTeachers = groups.reduce((sum, g) => sum + g.teacherCount, 0);
        return json(200, { totalGroups: groups.length, totalTeachers, groups });
      }

      if (parts[1] === 'settings' && parts.length === 2) {
        if (method === 'GET') {
          return json(200, await getSettings());
        }
        if (method === 'PUT') {
          const s = await getSettings();
          if (typeof body.paywallEnabled === 'boolean') s.paywallEnabled = body.paywallEnabled;
          await saveSettings(s);
          return json(200, s);
        }
      }

      return json(404, { error: 'Not found.' });
    }

    const tok = bearer(req);
    const tokRec = await getTokenRecord(tok);
    if (!tokRec) return json(401, { error: 'Invalid or expired session. Please sign in again.' });

    if (method === 'GET' && parts[0] === 'me' && parts.length === 1) {
      return json(200, { role: tokRec.role, name: tokRec.name, code: tokRec.code, tid: tokRec.tid });
    }

    if (parts[0] === 'groups' && parts.length >= 2) {
      const code = parts[1].toUpperCase();
      if (tokRec.code !== code) return json(403, { error: 'Not authorized for this group.' });
      const group = await getGroup(code);
      if (!group) return json(404, { error: 'Group not found.' });

      if (method === 'GET' && parts[2] === 'sow' && parts.length === 3) {
        return json(200, { data: group.sow.data, updatedAt: group.sow.updatedAt });
      }
      if (method === 'PUT' && parts[2] === 'sow' && parts.length === 3) {
        if (tokRec.role !== 'hod') return json(403, { error: 'HoD only.' });
        group.sow = { data: body.data, updatedAt: Date.now() };
        await saveGroup(group);
        return json(200, { ok: true });
      }
      if (method === 'PUT' && parts[2] === 'teachers' && parts[4] === 'progress' && parts.length === 5) {
        const tid = parts[3];
        if (tokRec.tid !== tid && tokRec.role !== 'hod') return json(403, { error: 'Not authorized.' });
        if (!group.teachers[tid]) return json(404, { error: 'Teacher not found.' });
        group.teachers[tid].progress = body.data || {};
        group.teachers[tid].updatedAt = Date.now();
        await saveGroup(group);
        return json(200, { ok: true });
      }
      if (method === 'PUT' && parts[2] === 'teachers' && parts[4] === 'preferences' && parts.length === 5) {
        const tid = parts[3];
        if (tokRec.tid !== tid && tokRec.role !== 'hod') return json(403, { error: 'Not authorized.' });
        if (!group.teachers[tid]) return json(404, { error: 'Teacher not found.' });
        group.teachers[tid].preferences = body || {};
        if (body.layoutPrefs && body.layoutPrefs.avatarColor) {
          group.teachers[tid].avatarColor = body.layoutPrefs.avatarColor;
        }
        await saveGroup(group);
        return json(200, { ok: true });
      }
      if (method === 'GET' && parts[2] === 'progress' && parts.length === 3) {
        const arr = Object.values(group.teachers).map(t => ({
          teacher: { id: t.id, name: t.name, avatarColor: t.avatarColor },
          progress: t.progress || {},
          updatedAt: t.updatedAt
        }));
        return json(200, arr);
      }
    }

    return json(404, { error: 'Not found.' });
  } catch (e) {
    return json(500, { error: 'Server error: ' + (e && e.message ? e.message : 'unknown') });
  }
};

export const config = { path: '/api/lf/*' };

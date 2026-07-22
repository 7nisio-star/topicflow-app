import { getStore } from '@netlify/blobs';
import crypto from 'crypto';
import Stripe from 'stripe';

const GROUPS = () => getStore('lf-groups');
const TOKENS = () => getStore('lf-tokens');
const RATE = () => getStore('lf-ratelimit');
const SETTINGS = () => getStore('lf-settings');
const BILLING = () => getStore('lf-billing');

function stripeClient() {
  const key = process.env.STRIPE_SECRET_KEY;
  return key ? new Stripe(key) : null;
}

// One-time payments, not Stripe subscriptions — school terms don't line up
// with fixed monthly billing cycles, so "termly"/"annual" just grant access
// for a fixed window from the moment of payment.
const PLAN_PRICES = {
  termly: { amount: 1500, name: 'TopicFlow — Termly', days: 120 },
  annual: { amount: 3000, name: 'TopicFlow — Annual (Academic Year)', days: 365 }
};

async function getBilling(code) {
  const b = await BILLING().get(code.toUpperCase(), { type: 'json', consistency: 'strong' });
  return b || { plan: null, paidUntil: 0 };
}
async function saveBilling(code, rec) {
  await BILLING().setJSON(code.toUpperCase(), rec);
}

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

// Group records get read-then-modified-then-written from multiple actors
// (HoD and several teachers, often within seconds of each other — e.g. two
// teachers saving progress, or a teacher joining right after the HoD sets
// the SoW). Netlify Blobs' default reads are eventually consistent, which
// showed up during testing as a genuine lost update: a stale read silently
// overwrote another teacher's just-saved data. Forcing strong consistency
// on every read that precedes a write closes that window.
async function getGroup(code) {
  return await GROUPS().get(code.toUpperCase(), { type: 'json', consistency: 'strong' });
}
async function saveGroup(g) {
  await GROUPS().setJSON(g.code, g);
}
async function getTokenRecord(tok) {
  if (!tok) return null;
  return await TOKENS().get(tok, { type: 'json', consistency: 'strong' });
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
  const s = await SETTINGS().get('global', { type: 'json', consistency: 'strong' });
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

    // Stripe webhook needs the raw request body for signature verification,
    // so it must be handled before the generic req.json() parse below (which
    // would otherwise consume the stream).
    if (req.method === 'POST' && path === '/billing/webhook') {
      const stripe = stripeClient();
      const whSecret = process.env.STRIPE_WEBHOOK_SECRET;
      if (!stripe || !whSecret) return json(400, { error: 'Webhook not configured.' });
      const sig = req.headers.get('stripe-signature');
      const raw = await req.text();
      let event;
      try {
        event = stripe.webhooks.constructEvent(raw, sig, whSecret);
      } catch (e) {
        return json(400, { error: 'Invalid signature.' });
      }
      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const code = session.metadata && session.metadata.groupCode;
        const planId = session.metadata && session.metadata.planId;
        const plan = PLAN_PRICES[planId];
        if (code && plan && session.payment_status === 'paid') {
          const existing = await getBilling(code);
          const base = Math.max(existing.paidUntil || 0, Date.now());
          const paidUntil = base + plan.days * 24 * 60 * 60 * 1000;
          await saveBilling(code, { plan: planId, paidUntil, updatedAt: Date.now(), lastSessionId: session.id });
        }
      }
      return json(200, { received: true });
    }

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
        createdAt: Date.now(),
        archived: false
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
      if (!settings.paywallEnabled) return json(200, { active: true });
      const code = parts[2];
      if (!code) return json(200, { active: true });
      const billing = await getBilling(code);
      const active = (billing.paidUntil || 0) > Date.now();
      return json(200, { active, plan: billing.plan || null, paidUntil: billing.paidUntil || null });
    }
    if (method === 'GET' && parts[0] === 'billing' && parts[1] === 'plans') {
      return json(200, [
        { id: 'termly', name: 'Termly', description: 'One payment, covers roughly a term', price: 15, period: '/ term' },
        { id: 'annual', name: 'Annual (Academic Year)', description: 'One payment for the whole academic year — best value', price: 30, period: '/ year' }
      ]);
    }
    if (method === 'POST' && parts[0] === 'billing' && parts[1] === 'checkout') {
      if (!(await allow(req, 'checkout', 20, 10 * 60 * 1000))) {
        return json(429, { error: 'Too many attempts. Please wait a few minutes and try again.' });
      }
      const stripe = stripeClient();
      if (!stripe) return json(400, { error: 'Billing is not set up yet, your account is free for now.' });
      const planId = body.planId;
      const groupCode = (body.groupCode || '').toUpperCase();
      const plan = PLAN_PRICES[planId];
      if (!plan) return json(400, { error: 'Unknown plan.' });
      const group = await getGroup(groupCode);
      if (!group) return json(404, { error: 'Group not found.' });
      const origin = req.headers.get('origin') || ('https://' + url.host);
      try {
        const session = await stripe.checkout.sessions.create({
          mode: 'payment',
          payment_method_types: ['card'],
          line_items: [{
            price_data: {
              currency: 'gbp',
              unit_amount: plan.amount,
              product_data: { name: plan.name + ' — ' + group.hodName }
            },
            quantity: 1
          }],
          metadata: { groupCode, planId },
          success_url: origin + '/?billing=success&code=' + groupCode + '&session_id={CHECKOUT_SESSION_ID}',
          cancel_url: origin + '/?billing=cancel'
        });
        return json(200, { checkoutUrl: session.url, checkoutId: session.id });
      } catch (e) {
        return json(500, { error: 'Could not start checkout: ' + (e && e.message ? e.message : 'unknown error') });
      }
    }
    // Confirms a checkout directly with Stripe using the session id returned
    // to the success page. This is the primary way payment gets recorded —
    // no webhook needed, which keeps setup to "paste in one API key."
    if (method === 'POST' && parts[0] === 'billing' && parts[1] === 'verify') {
      if (!(await allow(req, 'verify', 30, 10 * 60 * 1000))) {
        return json(429, { error: 'Too many attempts. Please wait a few minutes and try again.' });
      }
      const stripe = stripeClient();
      if (!stripe) return json(400, { error: 'Billing is not set up yet.' });
      const sessionId = body.sessionId;
      const groupCode = (body.groupCode || '').toUpperCase();
      if (!sessionId || !groupCode) return json(400, { error: 'Missing sessionId or groupCode.' });
      try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const meta = session.metadata || {};
        if (meta.groupCode !== groupCode) return json(403, { error: 'Session does not match this group.' });
        const plan = PLAN_PRICES[meta.planId];
        if (!plan) return json(400, { error: 'Unknown plan on session.' });
        if (session.payment_status !== 'paid') return json(200, { active: false });
        const existing = await getBilling(groupCode);
        const base = Math.max(existing.paidUntil || 0, Date.now());
        const paidUntil = base + plan.days * 24 * 60 * 60 * 1000;
        await saveBilling(groupCode, { plan: meta.planId, paidUntil, updatedAt: Date.now(), lastSessionId: session.id });
        return json(200, { active: true, plan: meta.planId, paidUntil });
      } catch (e) {
        return json(500, { error: 'Could not verify payment: ' + (e && e.message ? e.message : 'unknown error') });
      }
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
          const billing = await getBilling(g.code);
          groups.push({
            code: g.code,
            hodName: g.hodName,
            teacherCount: teachers.length,
            createdAt: g.createdAt,
            lastActivity: Math.max(...activityTimes),
            archived: !!g.archived,
            plan: billing.plan || null,
            paidUntil: billing.paidUntil || null
          });
        }
        groups.sort((a, b) => (b.lastActivity || 0) - (a.lastActivity || 0));
        const active = groups.filter(g => !g.archived);
        const totalTeachers = active.reduce((sum, g) => sum + g.teacherCount, 0);
        return json(200, {
          totalGroups: active.length,
          totalTeachers,
          archivedGroups: groups.length - active.length,
          groups
        });
      }

      if (method === 'PUT' && parts[1] === 'groups' && parts[3] === 'archive' && parts.length === 4) {
        const code = parts[2].toUpperCase();
        const g = await getGroup(code);
        if (!g) return json(404, { error: 'Group not found.' });
        g.archived = !!body.archived;
        await saveGroup(g);
        return json(200, { code: g.code, archived: g.archived });
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
          preferences: t.preferences || {},
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

// POST /api/login  { password } → seta cookie de sessão assinado (30 dias)
const crypto = require('crypto');

function sessionToken(secret) {
  return crypto.createHmac('sha256', secret).update('cp-auth-v1').digest('hex');
}

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método não permitido' });
  }
  const expected = process.env.PORTAL_PASSWORD || '';
  const secret = process.env.AUTH_SECRET || '';
  if (!expected || !secret) {
    return res.status(500).json({ error: 'Servidor sem PORTAL_PASSWORD/AUTH_SECRET configurados' });
  }
  const given = String((req.body && req.body.password) || '');
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!ok) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
  res.setHeader(
    'Set-Cookie',
    `cp_sess=${sessionToken(secret)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`
  );
  return res.status(200).json({ ok: true });
};

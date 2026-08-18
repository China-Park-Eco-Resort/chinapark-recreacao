// GET /api/entrar?t=<passe>&para=/admin/...
// Valida um passe emitido por chinapark.app (PASSE_SECRET compartilhado) e cria a
// sessão local (cookie cp_sess com o papel). Assim quem entrou pelo login único
// não digita senha de novo aqui.
const crypto = require('crypto');
const { tokenDe, PAPEIS } = require('../lib/auth');

module.exports = (req, res) => {
  const secret = process.env.PASSE_SECRET || '';
  const authSecret = process.env.AUTH_SECRET || '';
  if (!secret || !authSecret) return res.status(500).send('Servidor sem PASSE_SECRET/AUTH_SECRET');

  const t = String((req.query && req.query.t) || '');
  const [b64, sig] = t.split('.');
  if (!b64 || !sig) return res.redirect(302, '/admin/login');
  let corpo;
  try { corpo = Buffer.from(b64, 'base64url').toString('utf8'); } catch { return res.redirect(302, '/admin/login'); }
  const esperado = crypto.createHmac('sha256', secret).update(corpo).digest('hex');
  if (sig.length !== esperado.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(esperado))) {
    return res.redirect(302, '/admin/login');
  }
  const [papel, email, expStr] = corpo.split('|');
  if (!PAPEIS.includes(papel) || Date.now() > Number(expStr)) {
    return res.redirect(302, '/admin/login?expirado=1');
  }

  let para = String((req.query && req.query.para) || '/admin');
  if (!/^\/admin(\/[A-Za-z0-9_\-]*)?$/.test(para)) para = '/admin';

  res.setHeader('Set-Cookie',
    `cp_sess=${tokenDe(papel, authSecret)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
  return res.redirect(302, para);
};

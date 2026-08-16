// POST /api/login  { password } → identifica o papel pela senha e seta cookie assinado (30 dias)
//   PORTAL_PASSWORD_RECEPCAO  → papel recepcao (gerencia tudo)
//   PORTAL_PASSWORD_RECREACAO → papel recreacao (programação, cinema, cadastro)
const crypto = require('crypto');
const { tokenDe } = require('../lib/auth');

function igual(a, b) {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && A.length > 0 && crypto.timingSafeEqual(A, B);
}

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método não permitido' });
  }
  const secret = process.env.AUTH_SECRET || '';
  const senhas = {
    recepcao:  process.env.PORTAL_PASSWORD_RECEPCAO || '',
    recreacao: process.env.PORTAL_PASSWORD_RECREACAO || '',
  };
  if (!secret || !senhas.recepcao || !senhas.recreacao) {
    return res.status(500).json({ error: 'Servidor sem senhas/AUTH_SECRET configurados' });
  }
  const given = String((req.body && req.body.password) || '');
  const papel = igual(given, senhas.recepcao) ? 'recepcao'
              : igual(given, senhas.recreacao) ? 'recreacao' : null;
  if (!papel) return res.status(401).json({ error: 'Senha incorreta' });

  res.setHeader('Set-Cookie',
    `cp_sess=${tokenDe(papel, secret)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
  return res.status(200).json({ ok: true, papel });
};

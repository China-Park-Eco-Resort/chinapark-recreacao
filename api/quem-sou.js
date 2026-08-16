// GET /api/quem-sou → { papel } da sessão atual (para o portal montar a tela certa)
const { papelDoCookie } = require('../lib/auth');
module.exports = (req, res) => {
  const papel = papelDoCookie(req.headers.cookie, process.env.AUTH_SECRET || '');
  res.setHeader('Cache-Control', 'no-store');
  if (!papel) return res.status(401).json({ error: 'Não autenticado' });
  return res.status(200).json({ papel });
};

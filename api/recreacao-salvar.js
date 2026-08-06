// POST /api/recreacao-salvar  { chave, dados } → grava no Supabase.
// Exige o cookie cp_sess da equipe (mesmo HMAC do middleware) e usa o
// REC_WRITE_SECRET do servidor — nem o anon key nem o segredo tocam o cliente.
const crypto = require('crypto');

function sessionToken(secret) {
  return crypto.createHmac('sha256', secret).update('cp-auth-v1').digest('hex');
}

const CHAVES = ['programacao', 'jantares', 'feriados', 'guia'];

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método não permitido' });
  }
  const authSecret = process.env.AUTH_SECRET || '';
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;
  const writeSecret = process.env.REC_WRITE_SECRET;
  if (!authSecret || !url || !key || !writeSecret) {
    return res.status(500).json({ error: 'Servidor sem envs configuradas' });
  }

  const cookie = String(req.headers.cookie || '');
  const m = cookie.match(/(?:^|;\s*)cp_sess=([a-f0-9]{64})/);
  if (!m || m[1] !== sessionToken(authSecret)) {
    return res.status(401).json({ error: 'Não autenticado — faça login em /login.html' });
  }

  const chave = req.body && req.body.chave;
  const dados = req.body && req.body.dados;
  if (!CHAVES.includes(chave) || dados === undefined) {
    return res.status(400).json({ error: 'Informe chave (programacao|jantares|feriados|guia) e dados' });
  }

  try {
    const r = await fetch(`${url}/rest/v1/rpc/rec_salvar`, {
      method: 'POST',
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ _chave: chave, _dados: dados, _segredo: writeSecret }),
    });
    if (!r.ok) {
      return res.status(502).json({ error: 'Falha ao gravar no banco' });
    }
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(502).json({ error: 'Falha ao gravar no banco' });
  }
};

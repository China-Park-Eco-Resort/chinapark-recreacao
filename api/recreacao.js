// GET /api/recreacao → { programacao, jantares, feriados } (leitura pública)
// Os dados vivem no Supabase (schema recreacao) e são gravados pelo admin
// via /api/recreacao-salvar. As chaves do Supabase ficam só no servidor.
module.exports = async (req, res) => {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Método não permitido' });
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;
  if (!url || !key) {
    return res.status(500).json({ error: 'Servidor sem SUPABASE_URL/SUPABASE_ANON_KEY' });
  }
  try {
    const r = await fetch(`${url}/rest/v1/rpc/rec_carregar`, {
      method: 'POST',
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    if (!r.ok) {
      return res.status(502).json({ error: 'Falha ao consultar o banco' });
    }
    const dados = await r.json();
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json(dados);
  } catch (e) {
    return res.status(502).json({ error: 'Falha ao consultar o banco' });
  }
};

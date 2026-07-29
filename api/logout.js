// POST /api/logout → apaga o cookie de sessão
module.exports = (req, res) => {
  res.setHeader('Set-Cookie', 'cp_sess=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  return res.status(200).json({ ok: true });
};

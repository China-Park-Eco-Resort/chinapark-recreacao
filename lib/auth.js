// Papéis da equipe — a sessão carrega o papel dentro do token assinado (HMAC),
// então o cliente não consegue "se promover" trocando o cookie.
//
//   recepcao  → gerencia tudo
//   recreacao → programação de recreação, cinema (e futuramente o cadastro)
//
// Formato do cookie: cp_sess=<papel>.<hmac_hex>   onde hmac = HMAC(secret, 'cp-auth-v2:'+papel)
const crypto = require('crypto');

const PAPEIS = ['recepcao', 'recreacao'];

// o que cada papel pode abrir (prefixos de rota)
const PERMISSOES = {
  recepcao:  ['/admin'],                                    // tudo
  recreacao: ['/admin', '/admin/recreacao', '/admin/cinema', '/admin/cadastro'],
};

function assinar(secret, papel) {
  return crypto.createHmac('sha256', secret).update('cp-auth-v2:' + papel).digest('hex');
}

function tokenDe(papel, secret) {
  return `${papel}.${assinar(secret, papel)}`;
}

// devolve o papel se o cookie for válido, senão null
function papelDoCookie(cookieHeader, secret) {
  const m = String(cookieHeader || '').match(/(?:^|;\s*)cp_sess=([a-z]+)\.([a-f0-9]{64})/);
  if (!m || !secret) return null;
  const [, papel, sig] = m;
  if (!PAPEIS.includes(papel)) return null;
  const esperado = assinar(secret, papel);
  if (sig.length !== esperado.length) return null;
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(esperado)) ? papel : null;
}

function podeAcessar(papel, path) {
  const lista = PERMISSOES[papel];
  if (!lista) return false;
  if (papel === 'recepcao') return true;
  if (path === '/admin') return true;            // portal: todo perfil entra (vê só o seu)
  return lista.filter(p => p !== '/admin').some(p => path === p || path.startsWith(p + '/'));
}

module.exports = { PAPEIS, PERMISSOES, tokenDe, papelDoCookie, podeAcessar };

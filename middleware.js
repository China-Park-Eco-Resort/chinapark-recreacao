// Edge Middleware — tonochinapark.com.br
//
//   /            → Guia do Hóspede (público)
//   /admin       → Portal da equipe (login) — TODA a gestão vive em /admin/*
//   /admin/*     → gerenciadores (recreacao, cinema, musica, brinquedao, guia)
//
// A senha NÃO fica no código: mora na env PORTAL_PASSWORD (Vercel).
// O cookie cp_sess é um HMAC assinado com AUTH_SECRET, emitido por /api/login.

export const config = {
  matcher: [
    '/',
    '/admin', '/admin/:path*',
    // arquivos internos NÃO são acessíveis pelo nome — só via /admin/*
    '/admin-portal', '/admin-portal.html', '/admin-recreacao', '/admin-recreacao.html',
    '/admin-cinema', '/admin-cinema.html', '/admin-musica', '/admin-musica.html',
    '/admin-brinquedao', '/admin-brinquedao.html', '/admin-guia', '/admin-guia.html',
    '/admin-login', '/admin-login.html', '/admin-sem-permissao', '/admin-sem-permissao.html',
    '/conceito-a', '/conceito-a.html',
    '/conceito-b', '/conceito-b.html',
    '/calculadora-pensao-completa', '/calculadora-pensao-completa.html',
  ],
};

// dentro de /admin, o que abre sem senha
const LIVRES = new Set(['/admin/login', '/admin/sem-permissao', '/admin/entrar']);

// papéis: o que cada um pode abrir (espelho de lib/auth.js — Edge não usa require)
const PAPEIS = ['recepcao', 'recreacao'];
const PERMISSOES = {
  recepcao:  ['/admin'],
  recreacao: ['/admin', '/admin/recreacao', '/admin/cinema', '/admin/cadastro'],
};
function podeAcessar(papel, path) {
  if (papel === 'recepcao') return true;
  if (path === '/admin') return true;            // portal: todo perfil entra (vê só o seu)
  const lista = (PERMISSOES[papel] || []).filter(p => p !== '/admin');
  return lista.some(p => path === p || path.startsWith(p + '/'));
}

async function assinar(secret, papel) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode('cp-auth-v2:' + papel));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// devolve o papel da sessão ou null
async function papelDoCookie(cookieHeader, secret) {
  const m = String(cookieHeader || '').match(/(?:^|;\s*)cp_sess=([a-z]+)\.([a-f0-9]{64})/);
  if (!m || !secret || !PAPEIS.includes(m[1])) return null;
  return (m[2] === await assinar(secret, m[1])) ? m[1] : null;
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const host = (request.headers.get('host') || '').toLowerCase();
  const path = url.pathname;

  // www → raiz é feito no domínio (Vercel, 308) — nada a fazer aqui

  // raiz = Guia do Hóspede
  if (path === '/') return Response.redirect(new URL('/guia', url), 302);

  // a calculadora saiu do /admin: link antigo leva ao novo, sem senha
  if (path === '/admin/calculadora') {
    return Response.redirect(new URL('/calculadora', url), 308);
  }

  // área da equipe
  if (path === '/admin' || path.startsWith('/admin/')) {
    if (LIVRES.has(path)) return;
    const papel = await papelDoCookie(request.headers.get('cookie'), process.env.AUTH_SECRET);
    if (!papel) {
      const dest = new URL('/admin/login', url);
      dest.searchParams.set('next', path);
      return Response.redirect(dest, 302);
    }
    if (!podeAcessar(papel, path)) {
      return Response.redirect(new URL('/admin/sem-permissao', url), 302);
    }
    return;
  }

  // qualquer arquivo interno pelo nome direto: não existe
  return new Response('Não encontrado', { status: 404 });
}

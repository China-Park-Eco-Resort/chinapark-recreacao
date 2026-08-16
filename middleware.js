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
    '/admin-login', '/admin-login.html',
    '/conceito-a', '/conceito-a.html',
    '/conceito-b', '/conceito-b.html',
    '/calculadora-pensao-completa', '/calculadora-pensao-completa.html',
  ],
};

// dentro de /admin, o que abre sem senha
const LIVRES = new Set(['/admin/login', '/admin/calculadora']);

async function expectedToken(secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode('cp-auth-v1'));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const host = (request.headers.get('host') || '').toLowerCase();
  const path = url.pathname;

  if (host === 'www.tonochinapark.com.br') {
    return Response.redirect(new URL(path + url.search, 'https://tonochinapark.com.br'), 308);
  }

  // raiz = Guia do Hóspede
  if (path === '/') return Response.redirect(new URL('/guia', url), 302);

  // área da equipe
  if (path === '/admin' || path.startsWith('/admin/')) {
    if (LIVRES.has(path)) return;
    const secret = process.env.AUTH_SECRET;
    const cookie = request.headers.get('cookie') || '';
    const m = cookie.match(/(?:^|;\s*)cp_sess=([a-f0-9]{64})/);
    if (secret && m && m[1] === await expectedToken(secret)) return;
    const dest = new URL('/admin/login', url);
    dest.searchParams.set('next', path);
    return Response.redirect(dest, 302);
  }

  // qualquer arquivo interno pelo nome direto: não existe
  return new Response('Não encontrado', { status: 404 });
}

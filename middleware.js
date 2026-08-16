// Edge Middleware — dois públicos, dois domínios, um deploy.
//
//   tonochinapark.com.br      → HÓSPEDE: raiz = Guia; só páginas públicas; internas → 404
//   chinapark-app.vercel.app  → EQUIPE : raiz = Portal (login); internas exigem cookie
//
// A senha NÃO fica no código: mora na env PORTAL_PASSWORD (Vercel).
// O cookie cp_sess é um HMAC assinado com AUTH_SECRET, emitido por /api/login.

export const config = {
  matcher: [
    // raiz (decide o destino por domínio)
    '/',
    // internas — protegidas no domínio da equipe, invisíveis no do hóspede
    '/portal', '/portal.html',
    '/admin', '/admin.html',
    '/cinema-admin', '/cinema-admin.html',
    '/musica-admin', '/musica-admin.html',
    '/brinquedao-admin', '/brinquedao-admin.html',
    '/guia-admin', '/guia-admin.html',
    '/conceito-a', '/conceito-a.html',
    '/conceito-b', '/conceito-b.html',
    '/login', '/login.html',
    '/calculadora-pensao-completa', '/calculadora-pensao-completa.html',
  ],
};

const HOSPEDE_HOSTS = ['tonochinapark.com.br', 'www.tonochinapark.com.br'];

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
  const path = url.pathname.replace(/\.html$/, '');
  const ehHospede = HOSPEDE_HOSTS.includes(host);

  // www → raiz (domínio do hóspede)
  if (host === 'www.tonochinapark.com.br') {
    return Response.redirect(new URL(url.pathname + url.search, 'https://tonochinapark.com.br'), 308);
  }

  // raiz: cada público cai na sua casa
  if (path === '/' || path === '') {
    return Response.redirect(new URL(ehHospede ? '/guia' : '/portal', url), 302);
  }

  // domínio do hóspede não expõe nada interno (nem a tela de login)
  if (ehHospede) {
    return new Response('Não encontrado', { status: 404 });
  }

  // login e calculadora (recepção) são livres no domínio da equipe
  if (path === '/login' || path === '/calculadora-pensao-completa') return;

  // demais internas: exigem cookie da equipe
  const secret = process.env.AUTH_SECRET;
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(/(?:^|;\s*)cp_sess=([a-f0-9]{64})/);
  if (secret && m && m[1] === await expectedToken(secret)) {
    return; // autenticado — segue para a página
  }
  const dest = new URL('/login', url);
  dest.searchParams.set('next', url.pathname);
  return Response.redirect(dest, 302);
}

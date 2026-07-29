// Edge Middleware — protege as páginas internas/admin.
// A senha NÃO fica mais no código: mora na env var PORTAL_PASSWORD (Vercel).
// O cookie cp_sess é um HMAC assinado com AUTH_SECRET, emitido por /api/login.

export const config = {
  matcher: [
    '/portal.html',
    '/admin.html',
    '/cinema-admin.html',
    '/musica-admin.html',
    '/brinquedao-admin.html',
    '/calculadora-pensao-completa.html',
    '/conceito-a.html',
    '/conceito-b.html',
  ],
};

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
  const secret = process.env.AUTH_SECRET;
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(/(?:^|;\s*)cp_sess=([a-f0-9]{64})/);
  if (secret && m && m[1] === await expectedToken(secret)) {
    return; // autenticado — segue para a página
  }
  const url = new URL(request.url);
  const dest = new URL('/login.html', url);
  dest.searchParams.set('next', url.pathname);
  return Response.redirect(dest, 302);
}

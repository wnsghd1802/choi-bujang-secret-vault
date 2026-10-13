// Independent stage10 judges may use a separate trusted Supabase project for
// synthetic B notes. Auth-token issuer and database endpoint are distinct.
// The database endpoint is only read from trusted server environment variables.
export function getServerDb(env = {}) {
  const raw = env.SUPABASE_URL;
  if (typeof raw !== 'string' || raw !== raw.trim()) return null;
  let url;
  try { url = new URL(raw); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password
      || url.port || url.search || url.hash || url.pathname !== '/'
      || !/^[a-z0-9-]+\.supabase\.co$/u.test(url.hostname)) return null;
  const credential = [env.SUPABASE_SECRET_KEY, env.SUPABASE_SERVICE_ROLE_KEY]
    .find(key => typeof key === 'string' && key === key.trim()
      && key.length > 8 && !key.startsWith('sb_publishable_')
      && !key.startsWith('sb_anon_'));
  if (!credential) return null;
  return { url: url.origin, secretKey: credential };
}

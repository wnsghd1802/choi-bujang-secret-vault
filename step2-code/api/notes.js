import { createClient } from '@supabase/supabase-js';

export function createNotesHandler(env = process.env, clientFactory = createClient) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({ error: 'GET 요청만 지원합니다.' });
    }
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) {
      return res.status(503).json({ error: '서버 연결 설정이 필요합니다.' });
    }
    try {
      // Server-only client: never use a visitor's token or cookies here.
      const db = clientFactory(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      });
      const { data, error } = await db.from('notes').select('id,title,content')
        .order('id', { ascending: true }).limit(100)
        .abortSignal(AbortSignal.timeout(8000));
      if (error || !Array.isArray(data)) throw new Error('read failed');
      return res.status(200).json({ sampleMarker: 'SAMPLE_NOTE_1', notes: data });
    } catch {
      // Do not log or forward database errors containing sensitive details.
      return res.status(502).json({ error: '자료를 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.' });
    }
  };
}

// Stage 2 keeps this API public. Authentication belongs to stage 3.
export default createNotesHandler();

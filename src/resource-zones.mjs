// Distinct, server-side resource namespaces; existing notes.id UUIDs are preserved.
// These IDs are authorization references, not browser-controlled roles.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function resourceIdFor(zone, id) {
  if (!['memo', 'instructor_notice'].includes(zone) || typeof id !== 'string' || !UUID.test(id)) return null;
  return `${zone}:${id.toLowerCase()}`;
}

export function requestHasOnlyResourceId(req, id, routePrefix) {
  // Vercel places the dynamic path parameter in req.query.id.
  if (!resourceIdFor(routePrefix === '/api/notes' ? 'memo' : 'instructor_notice', id)) return false;
  const args = req.query ?? {};
  if (!args || typeof args !== 'object' || Array.isArray(args)
    || Object.keys(args).some(key => key !== 'id' && args[key] !== undefined)) return false;
  if (typeof req.url === 'string') {
    let address;
    try { address = new URL(req.url, 'https://request.invalid'); }
    catch { return false; }
    if (address.search || address.hash || address.pathname !== `${routePrefix}/${id}`) return false;
  }
  return true;
}

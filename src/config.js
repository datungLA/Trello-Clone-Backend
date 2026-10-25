import net from 'node:net';

export function trustedProxy(value) {
  if (value === undefined || value === '' || value === 'false') return false;
  if (/^[1-3]$/.test(value)) return Number(value);
  const entries = value.split(',').map(part => part.trim());
  if (!entries.length || entries.some(entry => {
    const [address, prefix, extra] = entry.split('/');
    const version = net.isIP(address);
    return !version || extra !== undefined || (prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) < (version === 4 ? 8 : 32) || Number(prefix) > (version === 4 ? 32 : 128)));
  })) throw new Error('TRUST_PROXY must be 1-3 hops or explicit bounded IP/CIDR entries.');
  return entries;
}
export function validateConfig(config) {
  if (!config.jwtSecret || config.jwtSecret.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters.');
  if (config.setupToken && config.setupToken.length < 32) throw new Error('BOOTSTRAP_SETUP_TOKEN must contain at least 32 characters.');
  if (config.trustProxy && !(Number.isInteger(config.trustProxy) && config.trustProxy >= 1 && config.trustProxy <= 3) && !Array.isArray(config.trustProxy)) throw new Error('TRUST_PROXY must be bounded.');
  if (Array.isArray(config.trustProxy) && (!config.trustProxy.length || !trustedProxy(config.trustProxy.join(',')))) throw new Error('TRUST_PROXY requires explicit networks.');
  const origins = [config.origin, ...(config.origins || [])];
  for (const origin of origins) {
    let url;
    try { url = new URL(origin); } catch { throw new Error('APP_ORIGIN and APP_ORIGINS require valid origins.'); }
    if (url.origin !== origin || url.username || url.password || !['http:', 'https:'].includes(url.protocol)) throw new Error('Application origins must be exact HTTP(S) origins without paths.');
    if (config.nodeEnv === 'production' && url.protocol !== 'https:') throw new Error('Production requires HTTPS application origins.');
  }
  if (config.nodeEnv === 'production') {
    if (!config.secure) throw new Error('Production requires secure cookies.');
    if (!config.trustProxy) throw new Error('Production requires bounded TRUST_PROXY.');
    if (!config.resendApiKey || !/^re_/.test(config.resendApiKey) || !config.mailFrom || !/[^\s<>]+@[^\s<>]+\.[^\s<>]+/.test(config.mailFrom)) throw new Error('Production requires RESEND_API_KEY and MAIL_FROM.');
    if (config.devMailDir) throw new Error('Production cannot use DEV_MAIL_DIR.');
  }
  return config;
}

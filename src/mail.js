import { mkdir, writeFile } from 'node:fs/promises';

export function resetDelivery(config, request = fetch, verification = false) {
  if (config.resendApiKey) {
    if (!config.mailFrom) throw new Error('MAIL_FROM is required when Resend is enabled.');
    return async ({ to, resetUrl, tokenHash }) => {
      const title = verification ? 'Verify your email' : 'Reset your password';
      const expiry = verification ? '24 hours' : '30 minutes';
      const safeUrl = resetUrl.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');
      const response = await request('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${config.resendApiKey}`, 'Content-Type': 'application/json', 'Idempotency-Key': `${verification ? 'email-verification' : 'password-reset'}-${tokenHash}` },
        signal: AbortSignal.timeout(10000),
        body: JSON.stringify({
          from: config.mailFrom,
          to: [to],
          subject: verification ? 'Verify your Trello Learning email' : 'Reset your Trello Learning password',
          text: `${title}: ${resetUrl}\n\nThis link expires in ${expiry} and can be used once. If you did not request this, you can ignore this email.`,
          html: `<h2>${title}</h2><p>Use the button below to ${verification ? 'verify your Trello Learning email.' : 'choose a new Trello Learning password.'}</p><p><a href="${safeUrl}" style="display:inline-block;padding:12px 20px;border-radius:8px;background:#0065ff;color:#fff;text-decoration:none">${title}</a></p><p>This link expires in ${expiry} and can be used once.</p><p>If you did not request a reset, you can ignore this email.</p>`,
        }),
      });
      if (!response.ok) throw Object.assign(new Error('Email delivery was rejected.'), { code: 'MAIL_DELIVERY_FAILED' });
    };
  }
  if (config.devMailDir && config.nodeEnv !== 'production') return async ({ to, resetUrl, userId }) => {
    await mkdir(config.devMailDir, { recursive: true, mode: 0o700 });
    await writeFile(`${config.devMailDir}/${userId}${verification ? '.verify' : ''}.json`, JSON.stringify({ to, resetUrl }), { mode: 0o600 });
  };
  return null;
}

export function boundedMailQueue({ concurrency = 2, capacity = 64 } = {}) {
  let active = 0;
  const pending = [];
  const idle = [];
  function pump() {
    while (active < concurrency && pending.length) {
      active++;
      Promise.resolve().then(pending.shift()).catch(() => console.error('Authentication email task failed.')).finally(() => {
        active--; pump();
        if (!active && !pending.length) idle.splice(0).forEach(resolve => resolve());
      });
    }
  }
  return {
    enqueue(task) { if (active + pending.length >= capacity) return false; pending.push(task); setImmediate(pump); return true; },
    drain() { return active || pending.length ? new Promise(resolve => idle.push(resolve)) : Promise.resolve(); },
  };
}

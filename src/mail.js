import { mkdir, writeFile } from 'node:fs/promises';

export function resetDelivery(config, request = fetch) {
  if (config.resendApiKey) {
    if (!config.mailFrom) throw new Error('MAIL_FROM is required when Resend is enabled.');
    return async ({ to, resetUrl, tokenHash }) => {
      const safeUrl = resetUrl.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');
      const response = await request('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${config.resendApiKey}`, 'Content-Type': 'application/json', 'Idempotency-Key': `password-reset-${tokenHash}` },
        signal: AbortSignal.timeout(10000),
        body: JSON.stringify({
          from: config.mailFrom,
          to: [to],
          subject: 'Reset your Trello Learning password',
          text: `Reset your password: ${resetUrl}\n\nThis link expires in 30 minutes and can be used once. If you did not request a reset, you can ignore this email.`,
          html: `<h2>Reset your password</h2><p>Use the button below to choose a new Trello Learning password.</p><p><a href="${safeUrl}" style="display:inline-block;padding:12px 20px;border-radius:8px;background:#0065ff;color:#fff;text-decoration:none">Reset password</a></p><p>This link expires in 30 minutes and can be used once.</p><p>If you did not request a reset, you can ignore this email.</p>`,
        }),
      });
      if (!response.ok) throw Object.assign(new Error('Email delivery was rejected.'), { code: 'MAIL_DELIVERY_FAILED' });
    };
  }
  if (config.devMailDir && config.nodeEnv !== 'production') return async ({ to, resetUrl, userId }) => {
    await mkdir(config.devMailDir, { recursive: true, mode: 0o700 });
    await writeFile(`${config.devMailDir}/${userId}.json`, JSON.stringify({ to, resetUrl }), { mode: 0o600 });
  };
  return null;
}

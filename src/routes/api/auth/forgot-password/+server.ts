import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { findUserByIdentifier, createPasswordResetTokenInDb } from '$lib/server/db';
import { randomToken, sha256Hex } from '$lib/server/security';
import { sendPasswordResetTelegramNotification } from '$lib/server/telegram';

const RESET_TOKEN_TTL_MINUTES = 15;

export const POST: RequestHandler = async ({ platform, request }) => {
  const db = platform?.env?.DB;
  if (!db) {
    return json({ error: 'Database is not configured' }, { status: 503 });
  }

  const contentType = request.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    return json({ error: 'Expected JSON body' }, { status: 400 });
  }

  const body = (await request.json().catch(() => null)) as { identifier?: string } | null;
  const identifier = body?.identifier?.trim().toLowerCase() ?? '';

  if (!identifier) {
    return json({ error: 'identifier (email or username) is required' }, { status: 400 });
  }
  if (identifier.length > 254) {
    return json({ error: 'identifier is too long' }, { status: 400 });
  }

  // Always return the same response whether user exists or not (prevent enumeration)
  const genericMessage: Record<string, unknown> = {
    ok: true,
    message: `If the account exists, a password reset token has been sent via available channels.`
  };

  const user = await findUserByIdentifier(db, identifier);
  if (!user) {
    return json(genericMessage);
  }

  // Check if user has password login enabled (not a disabled/soft-deleted account)
  const passwordRow = await db
    .prepare('SELECT password_hash FROM users WHERE id = ? LIMIT 1')
    .bind(user.id)
    .first<{ password_hash: string | null }>();

  if (!passwordRow?.password_hash) {
    // Silently succeed for accounts without password login (disabled)
    return json(genericMessage);
  }

  // Generate reset token
  const rawToken = randomToken();
  const tokenHash = await sha256Hex(rawToken);
  await createPasswordResetTokenInDb(db, user.id, tokenHash, RESET_TOKEN_TTL_MINUTES);

  // Try to send via Telegram
  let sentViaTelegram = false;
  if (user.telegramEnabled) {
    try {
      sentViaTelegram = await sendPasswordResetTelegramNotification(db, platform?.env, {
        displayName: user.displayName,
        email: user.email,
        resetToken: rawToken,
        ttlMinutes: RESET_TOKEN_TTL_MINUTES
      });
    } catch {
      // Telegram notification is best-effort
    }
  }

  // If Telegram is not configured or user doesn't have Telegram enabled,
  // return the token directly (acceptable for self-hosted/personal use)
  return json({
    ok: true,
    message: sentViaTelegram
      ? 'Password reset token has been sent to your Telegram.'
      : `Password reset token generated (valid for ${RESET_TOKEN_TTL_MINUTES} minutes). Use POST /api/auth/reset-password to complete reset.`,
    ...(sentViaTelegram ? {} : { resetToken: rawToken })
  });
};

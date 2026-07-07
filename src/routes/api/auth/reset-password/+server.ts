import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import {
  findValidPasswordResetTokenInDb,
  markPasswordResetTokenUsedInDb,
  updateUserPasswordInDb,
  getUserPasswordHashInDb
} from '$lib/server/db';
import { hashPassword, sha256Hex } from '$lib/server/security';

export const POST: RequestHandler = async ({ platform, request }) => {
  const db = platform?.env?.DB;
  if (!db) {
    return json({ error: 'Database is not configured' }, { status: 503 });
  }

  const contentType = request.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    return json({ error: 'Expected JSON body' }, { status: 400 });
  }

  const body = (await request.json().catch(() => null)) as { token?: string; password?: string } | null;
  const token = body?.token?.trim() ?? '';
  const password = body?.password ?? '';

  if (!token) {
    return json({ error: 'token is required' }, { status: 400 });
  }
  if (!password) {
    return json({ error: 'password is required' }, { status: 400 });
  }
  if (password.length < 8 || password.length > 128) {
    return json({ error: 'password must be 8-128 characters' }, { status: 400 });
  }

  // Find valid (not expired, not used) reset token
  const tokenHash = await sha256Hex(token);
  const validToken = await findValidPasswordResetTokenInDb(db, tokenHash);
  if (!validToken) {
    return json({ error: 'Reset token is invalid or expired' }, { status: 401 });
  }

  // Verify user still has password-based login (not soft-deleted)
  const existingHash = await getUserPasswordHashInDb(db, validToken.userId);
  if (!existingHash) {
    return json({ error: 'User account is not available for password reset' }, { status: 403 });
  }

  // Update password
  const passwordHash = await hashPassword(password);
  await updateUserPasswordInDb(db, validToken.userId, passwordHash);

  // Mark token as used (one-time use)
  await markPasswordResetTokenUsedInDb(db, validToken.id);

  // Revoke all existing login sessions for this user (force re-login)
  try {
    await db
      .prepare('DELETE FROM login_sessions WHERE user_id = ?')
      .bind(validToken.userId)
      .run();
  } catch {
    // Session revocation is best-effort
  }

  return json({
    ok: true,
    message: 'Password has been reset successfully. Please login with your new password.'
  });
};

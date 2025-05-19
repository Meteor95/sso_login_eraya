import { Elysia } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import { parse } from 'cookie';

const accessJwtPlugin = jwt({
  name: 'accessJwt',
  secret: process.env.JWT_SECRET ?? 'No Secret',
  exp: '15m',
});

const refreshJwtPlugin = jwt({
  name: 'refreshJwt',
  secret: process.env.JWT_SECRET ?? 'No Secret',
  exp: '30d',
});

// Ini akan jadi plugin yang dipakai oleh Elysia
export const accessJwt = accessJwtPlugin;
export const refreshJwt = refreshJwtPlugin;

// Tambahkan akses langsung ke sign function
export const accessJwtInstance = await accessJwtPlugin.setup?.({});
export const refreshJwtInstance = await refreshJwtPlugin.setup?.({});

export const authWithRefresh = new Elysia()
  .use(accessJwt)
  .use(refreshJwt)
  .derive(async ({ accessJwt, refreshJwt, headers, set }) => {
    const bearer = headers.authorization?.replace('Bearer ', '');
    const cookies = parse(headers.cookie || '');
    const refreshToken = cookies.refresh_token;

    let accessPayload = null;

    // 1. Coba verifikasi access token
    if (bearer) {
      accessPayload = await accessJwt.verify(bearer).catch(() => null);
    }

    // 2. Kalau access token masih valid
    if (accessPayload) {
      return { user: accessPayload };
    }

    // 3. Kalau access token expired, coba refresh token
    if (refreshToken) {
      const refreshPayload = await refreshJwt.verify(refreshToken).catch(() => null);

      if (refreshPayload && refreshPayload.type === 'refresh') {
        const newAccessToken = await accessJwt.sign({
          id: refreshPayload.id,
          username: refreshPayload.username,
        });

        // Kirim token baru via response header
        set.headers['x-access-token'] = newAccessToken;

        return {
          user: {
            id: refreshPayload.id,
            username: refreshPayload.username,
          },
        };
      }
    }

    // 4. Kalau semua gagal
    set.status = 401;
    throw new Error('Unauthorized: Invalid or expired token');
  });

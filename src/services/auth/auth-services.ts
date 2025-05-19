import { db } from "@database/connection";
import { sso_users, sso_services, sso_users_login  } from "@database/schema";
import { eq, or, and, isNull, sql } from "drizzle-orm";
import redisHelper from "@helpers/redisHelper";
import { accessJwtInstance, refreshJwtInstance } from '@middlewares/jwt_auth';

export class AuthService {
    
    static async processLoginSSO(data: {
      username: string
      password: string
      fingerprint: string
      login_from: string
    }) {
      const result = await db.transaction(async (trx) => {
        const resultUser = await db
          .select()
          .from(sso_users)
          .where(
            and(
              or(
                eq(sso_users.username, data.username),
                eq(sso_users.email, data.username)
              ),
              isNull(sso_users.deleted_at)
            )
          )
    
        if (resultUser.length === 0) return 0
        if (!resultUser[0].status) return -2
    
        const isMatch = await Bun.password.verify(data.password, resultUser[0].password)
        if (!isMatch) return 0

        const user = resultUser[0]
        const hasLoggedInBefore = await db
          .select({ count: sql<number>`COUNT(*)` })
          .from(sso_users_login)
          .where(
            and(
              eq(sso_users_login.deviced_id, data.fingerprint),
              eq(sso_users_login.user_id, user.id)
            )
          )
          .limit(1)

        let accessToken: string
        let refreshToken: string
        
        if (hasLoggedInBefore[0].count == 0) {
          
          if (hasLoggedInBefore[0].count >= user.max_allowed_login) return -1
          
          await trx.insert(sso_users_login).values({
            user_id: user.id,
            deviced_id: data.fingerprint,
            created_at: new Date(),
          });
          accessToken = await accessJwtInstance.sign({
            id: user.id,
            username: user.username,
            type: 'access',
          });

          refreshToken = await refreshJwtInstance.sign({
            id: user.id,
            username: user.username,
            type: 'refresh',
          });
          
          await redisHelper.set(`accessToken:${user.uuid}`, { token: accessToken }, 60 * 60 * 24 * 7)
          await redisHelper.set(`refreshToken:${user.uuid}`, { refresh_token: refreshToken }, 60 * 60 * 24 * 30)
        } else {
          const session = await redisHelper.get<{ token: string }>(`accessToken:${user.uuid}`)
          const refreshSession = await redisHelper.get<{ refresh_token: string }>(`refreshToken:${user.uuid}`)
    
          if (!session?.token || !refreshSession?.refresh_token) {
            throw new Error('Token not found in Redis or session is expired')
          }
    
          accessToken = session.token
          refreshToken = refreshSession.refresh_token
        }
    
        const resultService = await db
          .select()
          .from(sso_services)
          .where(eq(sso_services.user_id, user.id))
    
        return {
          uuid: user.uuid,
          username: user.username,
          token: accessToken,
          refresh_token: refreshToken,
          service: resultService,
        }
      })
    
      return result
    }
    
    static async processRegisterSSO(data: { 
        uuidv7: string;
        email: string;
        phone: string;
        username: string;
        password: string;
        role: number;
        registration_number: string;
        status: boolean;
        max_allowed_login: number;
        created_at: Date;
    }) {
        const resultUser = await db.select()
            .from(sso_users)
            .where(
                or(
                    eq(sso_users.username, data.username),
                    eq(sso_users.email, data.email),
                    eq(sso_users.registration_number, data.registration_number)
                )
            )
            .limit(1);

        if (resultUser.length > 0) {
            return {
                success: false,
                username: resultUser[0].username,
                email: resultUser[0].email,
                registration_number: resultUser[0].registration_number,
            };
        }
        const hasher = new Bun.CryptoHasher("sha256");
        hasher.update(`eraya_digital_${data.uuidv7.replace(/-/g, '')}`);
        const result = await db.insert(sso_users)
            .values({
                uuid: data.uuidv7,
                email: data.email,
                phone: data.phone,
                username: data.username,
                password: data.password,
                role: data.role,
                registration_number: data.registration_number,
                status: data.status,
                max_allowed_login: data.max_allowed_login,
                token: hasher.digest("hex"),
                created_at: data.created_at
            })
            .returning({ 
                id: sso_users.id, 
                username: sso_users.username 
            });

        return result;
    }
}
import type { jwt } from '@elysiajs/jwt'

let jwtInstance: JWT

export function setJwtInstance(jwt: JWT) {
  jwtInstance = jwt
}

export async function signToken(payload: object, expiresIn = '7d') {
  if (!jwtInstance) throw new Error('JWT instance not set')
  return jwtInstance.sign(payload, { exp: expiresIn })
}

import { z } from "zod"
import { randomUUIDv7 } from "bun"
import { handleError } from "@helpers/handleError"
import { AuthService } from "@services/auth/auth-services"

export const loginSSO = async ({ body, set }: any) => {
  const schema = z.object({
    username: z.string(),
    password: z.string().min(6),
    fingerprint: z.string(),
    login_from: z.string(),
  })

  try {
    const data = schema.parse(body)

    const resultLogin = await AuthService.processLoginSSO({
      username: data.username,
      password: data.password,
      fingerprint: data.fingerprint,
      login_from: data.login_from,
    })

    let is_success = true;
    let messages = `Login successful for username: ${data.username}`;
    let dataLogin: typeof resultLogin | null = resultLogin;
    
    switch (resultLogin) {
      case 0:
        messages = `Login failed because the username or password is incorrect, or the account has been deleted from our database.`;
        is_success = false;
        dataLogin = null;
        break;
      case -2:
        messages = `Login failed because your account is disabled. Please contact the administrator.`;
        is_success = false;
        dataLogin = null;
        break;
    }

    return {
      success: is_success,
      message: messages,
      data: dataLogin,
    };
    

  } catch (e) {
    return handleError(e, `Something Error when users do Login with username ${body?.username}. Please contact the administrator.`)
  }
}

export const registerSSO = async ({ body, set }: any) => {
  const schema = z.object({
    email: z.string().email(),
    phone: z.string().min(10),
    username: z.string().min(3),
    password: z.string().min(6),
    role: z.number().int().positive(),
    registration_number: z.string().min(5),
  })

  try {
    const data = schema.parse(body)

    const bcryptHashPassword = await Bun.password.hash(data.password, {
      algorithm: "bcrypt",
      cost: process.env.BCRYPT_COST ? parseInt(process.env.BCRYPT_COST) : 12,
    })

    const resultRegister = await AuthService.processRegisterSSO({
      uuidv7: randomUUIDv7(),
      email: data.email,
      phone: data.phone,
      username: data.username,
      password: bcryptHashPassword,
      role: data.role,
      registration_number: data.registration_number,
      status: false,
      max_allowed_login: 5,
      created_at: new Date(),
    })

    let messages = `Registration successful for username : ${data.username}`
    let is_success = true
    let data_result = resultRegister

    if ("success" in resultRegister && !resultRegister.success) {
      messages = `Registration failed because username or email or registration number already exists.`
      is_success = false
    }

    set.status = is_success ? 201 : 400
    return {
      success: is_success,
      message: messages,
      data: data_result,
    }

  } catch (e) {
    return handleError( e, `Something Error when users do Register username ${body?.username}. Please contact the administrator.`)
  }
}

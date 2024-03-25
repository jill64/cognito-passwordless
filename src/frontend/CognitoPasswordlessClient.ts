import {
  AdminCreateUserCommand,
  AdminGetUserCommand,
  AdminInitiateAuthCommand,
  AdminRespondToAuthChallengeCommand,
  CognitoIdentityProviderClient,
  GetUserCommand,
  InitiateAuthCommand,
  RevokeTokenCommand,
  type AuthenticationResultType
} from '@aws-sdk/client-cognito-identity-provider'
import { attempt } from '@jill64/attempt'
import { CookieSerializeOptions } from 'cookie'
import crypto from 'node:crypto'
import { scanner, string } from 'typescanner'

export class CognitoPasswordlessClient {
  private cognito
  private cookies
  private COGNITO_CLIENT_ID
  private COGNITO_CLIENT_SECRET
  private COGNITO_USER_POOL_ID

  constructor(
    awsCredential: {
      accessKeyId: string
      secretAccessKey: string
      region: string
    },
    cognitoCredential: {
      clientId: string
      clientSecret: string
      userPoolId: string
    },
    cookies: {
      set: (
        name: string,
        value: string,
        options?: CookieSerializeOptions
      ) => void
      delete: (name: string, options?: CookieSerializeOptions) => void
      get: (name: string) => string | undefined
    }
  ) {
    this.cognito = new CognitoIdentityProviderClient({
      region: awsCredential.region,
      credentials: {
        accessKeyId: awsCredential.accessKeyId,
        secretAccessKey: awsCredential.secretAccessKey
      }
    })

    this.COGNITO_CLIENT_ID = cognitoCredential.clientId
    this.COGNITO_CLIENT_SECRET = cognitoCredential.clientSecret
    this.COGNITO_USER_POOL_ID = cognitoCredential.userPoolId

    this.cookies = cookies
  }

  private async get_user(access_token: string | undefined) {
    if (!access_token) {
      return null
    }

    try {
      const user = await this.cognito.send(
        new GetUserCommand({
          AccessToken: access_token
        })
      )

      if (!user) {
        return null
      }

      return user
    } catch {
      return null
    }
  }

  private async set_cookies(
    AuthenticationResult: AuthenticationResultType | undefined
  ) {
    const { AccessToken, RefreshToken, IdToken, ExpiresIn } =
      AuthenticationResult ?? {}

    const cookieOptions: CookieSerializeOptions = {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: ExpiresIn,
      path: '/'
    }

    if (AccessToken && IdToken && RefreshToken) {
      this.cookies.set('id_token', IdToken, cookieOptions)
      this.cookies.set('access_token', AccessToken, cookieOptions)
      this.cookies.set('refresh_token', RefreshToken, {
        ...cookieOptions,
        maxAge: 30 * 24 * 60 * 60
      })

      const cognito_user = await this.get_user(AccessToken)

      if (cognito_user?.Username) {
        this.cookies.set('cognito_id', cognito_user.Username, {
          ...cookieOptions,
          maxAge: 30 * 24 * 60 * 60
        })
      }
    }
  }

  private async exchange_refresh_token() {
    const refresh_token = this.cookies.get('refresh_token')
    const cognito_id = this.cookies.get('cognito_id')

    if (!refresh_token || !cognito_id) {
      return null
    }

    try {
      const { AuthenticationResult } = await this.cognito.send(
        new InitiateAuthCommand({
          AuthFlow: 'REFRESH_TOKEN',
          AuthParameters: {
            REFRESH_TOKEN: refresh_token,
            SECRET_HASH: this.gen_hash(cognito_id)
          },
          ClientId: this.COGNITO_CLIENT_ID
        })
      )

      await this.set_cookies(AuthenticationResult)

      return this.get_user(AuthenticationResult?.AccessToken)
    } catch (e) {
      console.error('Exchange Refresh Token Error:', e)
      return null
    }
  }

  private gen_hash(value: string) {
    return crypto
      .createHmac('sha256', this.COGNITO_CLIENT_SECRET)
      .update(`${value}${this.COGNITO_CLIENT_ID}`)
      .digest('base64')
  }

  async auth() {
    const access_token = this.cookies.get('access_token')

    const user =
      (await this.get_user(access_token)) ??
      (await this.exchange_refresh_token())

    return user
  }

  async signup(email: string) {
    await this.cognito.send(
      new AdminCreateUserCommand({
        UserPoolId: this.COGNITO_USER_POOL_ID,
        Username: email,
        MessageAction: 'SUPPRESS'
      })
    )
    return await this.sendEmail(email)
  }

  async existsUser(email: string) {
    try {
      const result = await this.cognito.send(
        new AdminGetUserCommand({
          UserPoolId: this.COGNITO_USER_POOL_ID,
          Username: email
        })
      )
      return !!result.Username
    } catch (e) {
      const is_error = scanner({
        name: string
      })
      return is_error(e) && e?.name === 'UserNotFoundException' ? false : true
    }
  }

  async sendEmail(email: string) {
    const { ChallengeName, Session } = await this.cognito.send(
      new AdminInitiateAuthCommand({
        AuthFlow: 'CUSTOM_AUTH',
        AuthParameters: {
          USERNAME: email,
          SECRET_HASH: this.gen_hash(email)
        },
        UserPoolId: this.COGNITO_USER_POOL_ID,
        ClientId: this.COGNITO_CLIENT_ID
      })
    )

    if (ChallengeName !== 'CUSTOM_CHALLENGE') {
      throw new Error(
        'Cognito Passwordless: ChallengeName is not CUSTOM_CHALLENGE'
      )
    }

    if (!Session) {
      throw new Error('Cognito Passwordless: Session is empty')
    }

    return Session
  }

  async login({
    session,
    email,
    code
  }: {
    session: string
    email: string
    code: string
  }) {
    const { AuthenticationResult, Session } = await this.cognito.send(
      new AdminRespondToAuthChallengeCommand({
        ChallengeName: 'CUSTOM_CHALLENGE',
        ChallengeResponses: {
          USERNAME: email,
          SECRET_HASH: this.gen_hash(email),
          ANSWER: code
        },
        Session: session,
        ClientId: this.COGNITO_CLIENT_ID,
        UserPoolId: this.COGNITO_USER_POOL_ID
      })
    )

    if (!AuthenticationResult) {
      return Session
    }

    await this.set_cookies(AuthenticationResult)
  }
  async logout() {
    const refresh_token = this.cookies.get('refresh_token')

    await attempt(() =>
      this.cognito.send(
        new RevokeTokenCommand({
          Token: refresh_token,
          ClientId: this.COGNITO_CLIENT_ID
        })
      )
    )

    const cookie_options: CookieSerializeOptions = {
      path: '/'
    }

    this.cookies.delete('cognito_id', cookie_options)
    this.cookies.delete('id_token', cookie_options)
    this.cookies.delete('access_token', cookie_options)
    this.cookies.delete('refresh_token', cookie_options)
  }
}

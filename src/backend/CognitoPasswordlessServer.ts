import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses'
import { customAlphabet } from 'nanoid'
import { CreateChallengeEvent } from './types/CreateChallengeEvent.js'
import { DefineChallengeEvent } from './types/DefineChallengeEvent.js'
import { VerifyChallengeEvent } from './types/VerifyChallengeEvent.js'

export class CognitoPasswordlessServer {
  private ses
  private verifyMail
  private retryLimit
  private expire
  private createCode

  constructor(
    region: string,
    verifyMail: {
      source: string
      subject: string
      body: (code: string) => string
    },
    params?: {
      retryLimit?: number
      expire?: number
      createCode?: () => string
    }
  ) {
    this.retryLimit = params?.retryLimit ?? 3
    this.createCode = params?.createCode
    this.expire = params?.expire ?? 1000 * 60 * 5
    this.verifyMail = verifyMail
    this.ses = new SESClient({ region })
  }

  defineChallenge(event: DefineChallengeEvent) {
    const { request } = event
    const { session } = request

    event.response.challengeName = 'CUSTOM_CHALLENGE'

    if (session.length >= this.retryLimit) {
      event.response.issueTokens = false
      event.response.failAuthentication = true

      return event
    }

    if (session.length > 0) {
      const { challengeName, challengeResult } =
        request.session[session.length - 1]

      if (challengeName === 'CUSTOM_CHALLENGE' && challengeResult) {
        event.response.issueTokens = true
        event.response.failAuthentication = false

        return event
      }
    }

    event.response.issueTokens = false
    event.response.failAuthentication = false

    return event
  }

  async createChallenge(event: CreateChallengeEvent) {
    const { email } = event.request.userAttributes
    const { session } = event.request

    event.response.publicChallengeParameters = {
      email
    }

    const latest = session[session.length - 1]

    const key = latest
      ? latest.challengeMetadata
      : this.createCode?.() ??
        customAlphabet('23456789ABCDEFGHJKLMNPQRSTUVWXYZ')(8)

    if (!latest) {
      event.response.challengeMetadata = key
    }

    const input = {
      Destination: {
        ToAddresses: [email]
      },
      Message: {
        Body: {
          Text: {
            Charset: 'UTF-8',
            Data: this.verifyMail.body(key)
          }
        },
        Subject: {
          Charset: 'UTF-8',
          Data: this.verifyMail.subject
        }
      },
      Source: this.verifyMail.source
    }

    if (session.length === 0) {
      await this.ses.send(new SendEmailCommand(input))
    }

    const expired = (Date.now() + this.expire).toString()

    event.response.privateChallengeParameters = {
      email,
      key,
      expired
    }

    return event
  }

  verifyChallenge(event: VerifyChallengeEvent) {
    const { request } = event
    const { privateChallengeParameters, challengeAnswer } = request

    event.response.answerCorrect =
      privateChallengeParameters.key == challengeAnswer &&
      Date.now() < Number(privateChallengeParameters.expired) &&
      privateChallengeParameters.email == request.userAttributes.email

    return event
  }
}

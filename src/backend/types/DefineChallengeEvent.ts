export type DefineChallengeEvent = {
  request: {
    userAttributes: {
      sub: string
      email: string
    }
    session: {
      challengeName: 'CUSTOM_CHALLENGE'
      challengeResult: boolean
      challengeMetadata: string
    }[]
    userNotFound: boolean
  }
  response: {
    challengeName: 'CUSTOM_CHALLENGE'
    issueTokens: boolean
    failAuthentication: boolean
  }
}

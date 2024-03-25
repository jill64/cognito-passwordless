export type CreateChallengeEvent = {
  request: {
    userAttributes: {
      sub: string
      email: string
    }
    challengeName: 'CUSTOM_CHALLENGE'
    session: {
      challengeName: 'CUSTOM_CHALLENGE'
      challengeResult: boolean
      challengeMetadata: string
    }[]
    userNotFound: boolean
  }
  response: {
    publicChallengeParameters: {
      email: string
    }
    privateChallengeParameters: {
      email: string
      key: string
      expired: string
    }
    challengeMetadata: string
  }
}

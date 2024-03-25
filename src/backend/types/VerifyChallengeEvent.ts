export type VerifyChallengeEvent = {
  request: {
    userAttributes: {
      sub: string
      email: string
    }
    privateChallengeParameters: {
      email: string
      key: string
      expired: string
    }
    challengeAnswer: string
    userNotFound: boolean
  }
  response: {
    answerCorrect: boolean
  }
}

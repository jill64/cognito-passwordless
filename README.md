<!----- BEGIN GHOST DOCS HEADER ----->
<!----- END GHOST DOCS HEADER ----->

## Installation

```sh
npm i cognito-passwordless
```

## Usage

### Frontend

```ts
import { CognitoPasswordless } from 'cognito-passwordless';

const client = new CognitoPasswordlessClient(
    // AWS Credential
    {
      accessKeyId: string
      secretAccessKey: string
      region: string
    },
    // Cognito Credential
    {
      clientId: string
      clientSecret: string
      userPoolId: string
    },
    // Cookies Handler
    {
      set: (
        name: string,
        value: string,
        options?: CookieSerializeOptions
      ) => void
      delete: (name: string, options?: CookieSerializeOptions) => void
      get: (name: string) => string | undefined
    })

// Authenticate
const userInfo = await client.auth()

// Signup
const email = 'email@example.com'
const session = await client.signup(email)
await login({
  session,
  email,
  code: 'OTP-CODE'
})

// Login
const email = 'email@example.com'
const session = await client.sendEmail(email)
await login({
  session,
  email,
  code: 'OTP-CODE'
})

// Logout
await client.logout()
```

### Backend

Please deploy these Lambda functions properly.

```ts
import { CognitoPasswordlessServer } from 'cognito-passwordless';

const server = new CognitoPasswordlessServer(
  region: string,
  // Verify Mail
  {
    source: string
    subject: string
    body: (code: string) => string
  }
)

// Define Challenge Lambda Function
export const handle = server.defineChallenge

// Create Challenge Lambda Function
export const handle = server.createChallenge

// Verify Challenge Lambda Function
export const handle = server.verifyChallenge
```

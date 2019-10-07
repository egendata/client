# @egendata/client

![License](https://flat.badgen.net/github/license/egendata/client)
![Dependabot](https://flat.badgen.net/dependabot/egendata/client?icon=dependabot)
![Travis CI](https://flat.badgen.net/travis/egendata/client?icon=travis)
![Github release](https://flat.badgen.net/github/release/egendata/client?icon=github)
![npm version](https://flat.badgen.net/npm/v/@egendata/client?icon=npm)

Client library for Egendata operator

## Install

`npm install @egendata/client`

## Create client

```javascript
const { create } = require('@egendata/client')

const config = {
  displayName: 'The name of your service',
  description: 'A nice description of your fantastic service',
  clientId: 'https://mycv.work', // Application domain with protocol
  operator: 'https://smoothoperator.work', // URL of Operator
  clientKeys: {
    publicKey: '-----BEGIN RSA PUBLIC KEY-----\nMIGJ...',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIICX...'
  },
  jwksPath: '/jwks',     // endpoint for keys in jwks format
  eventsPath: '/events'  // endpoint for events - webhook style
}
const client = create(config)
```

[How do I generate my client keys?](#generate-a-keypair-using-openssl?)

## Provide routes

```javascript
const express = require('express')
const app = express()

// Routes used by the operator
app.use(client.routes)
```


## Connecting to Operator
```
await client.connect()
```

## Create login URL
To enable users (who already have approved consents) to log in present this as a QR code so they can scan it with the Egendata-app on their phone.
```
const loginUrl = client.login.getUrl(sessionId)
```
When a user scans the code and logs in you will get a LOGIN_APPROVED event (see below) which contains the sessionId they logged in to.

## Create consent request
```
const pendingRequest = client.consents.request(consentRequestData)
```
where consentRequestData is
```
{
  scope: [
    {
      domain: 'https://mycv.work', // Application domain with protocol
      area: 'work_experience', // Name of the subset of data covered by this consent, something which makes sense in your domain
      description: 'A list of your work experience with dates.', // Description of the contents of the data area
      permissions: [ 'write' ], // Can be read or write
      purpose: 'In order to create a CV using our website.',
      lawfulBasis: 'CONSENT' // One of 'CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTERESTS', 'PUBLIC_TASK', 'LEGITIMATE_INTERESTS'
    }
  ],
  expiry: 515185155 // a UNIX timestamp of when the consent will expire
}
```
and pendingRequest contains
```
{
  id: // v4 uuid of the consent request
  url:
  expires:
}
```
when this is approved by a user it triggers a CONSENT_APPROVED event (see below)

## Subscribe to events

```javascript
client.events.on('CONSENT_APPROVED', consent => {
  // take action (eg. log in and redirect user)
})

client.events.on('LOGIN_APPROVED', consent => {
  // log in and redirect the session which has the provided sessionId
})
```

### Consent format

```javascript
{
  id: '78c2b714-222f-42fa-8ffa-ff0d6366c856', // uuid for consent
  scope: [
    {
      domain: 'https://mycv.work', // Application domain with protocol
      area: 'work_experience', // Name of the subset of data covered by this consent, something which makes sense in your domain
      description: 'A list of your work experience with dates.', // Description of the contents of the data area
      permissions: [ 'write' ], // Can be read or write
      purpose: 'In order to create a CV using our website.',
      lawfulBasis: 'CONSENT' // One of 'CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTERESTS', 'PUBLIC_TASK', 'LEGITIMATE_INTERESTS'
    }
  ]
}
```

### Login request format
User logs in by scanning a QR-code containing:
`egendata://login/PAYLOAD`

where PAYLOAD is a base64url encoded (RFC4648) JSON string containing:
```javascript
{
  clientId: 'https://mycv.work',
  sessionId: '84845151884' // This is any string with which you can uniquely identify this user session
}
```

## Generate a keypair using OpenSSL
_Prerequisite:_ You will need to have [OpenSSL](http://www.openssl.org/) installed on your system.

1. Generate a RSA keypair with a 2048 bit private key
```
$ openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
 ....................................................................+++
 ....................................................+++
```
2. Extract the public key

```
$ openssl rsa -pubout -in private_key.pem -out public_key.pem
writing RSA key
```

You will now have a suitable RSA keypair in the files `private_key.pem` and `public_key.pem`

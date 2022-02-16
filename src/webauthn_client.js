const log_el = document.getElementById('log')

function log(...messages) {
  console.log(...messages)
  log_el.innerText += '\n' + messages.map(m => JSON.stringify(m, null, 2)).join(' ')
}

function error(message) {
  console.error(message)
  log_el.innerText += '\n' + message
  throw Error('got error:' + message)
}

const asArrayBuffer = v => Uint8Array.from(atob(v.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0))
const asBase64 = ab => btoa(String.fromCharCode(...new Uint8Array(ab)))

async function getPublicKey(path, element) {
  const user_id = document.getElementById(element).value
  const r = await fetch(`/${path}/${user_id}/`)
  if (r.status !== 200) {
    error(`Unexpected response ${r.status}: ${await r.text()}`)
  }
  return await r.json()
}

async function post(path, element, creds) {
  const user_id = document.getElementById(element).value
  const {attestationObject, clientDataJSON, signature, authenticatorData} = creds.response
  const data = {
    id: creds.id,
    rawId: asBase64(creds.rawId),
    response: {
      attestationObject: asBase64(attestationObject),
      clientDataJSON: asBase64(clientDataJSON),
    }
  }
  if (signature) {
    data.response.signature = asBase64(signature)
    data.response.authenticatorData = asBase64(authenticatorData)
  }
  const r2 = await fetch(`/${path}/${user_id}/`, {
    method: 'POST',
    body: JSON.stringify(data),
    headers: {'content-type': 'application/json'}
  })
  if (r2.status !== 200) {
    error(`Unexpected response ${r2.status}: ${await r2.text()}`)
  }
}

async function register() {
  const publicKey = await getPublicKey('register', 'user-id-register')
  console.log('register get response:', publicKey)
  publicKey.user.id = asArrayBuffer(publicKey.user.id)
  publicKey.challenge = asArrayBuffer(publicKey.challenge)
  let creds
  try {
      creds = await navigator.credentials.create({publicKey})
  } catch (err) {
    log('refused:', err.toString())
    return
  }
  await post('register', 'user-id-register', creds)
  log('registration successful')
}

async function authenticate() {
  const publicKey = await getPublicKey('auth', 'user-id-auth')
  console.log('auth get response:', publicKey)
  publicKey.challenge = asArrayBuffer(publicKey.challenge)
  publicKey.allowCredentials[0].id = asArrayBuffer(publicKey.allowCredentials[0].id)
  let creds
  try {
      creds = await navigator.credentials.get({publicKey})
  } catch (err) {
    log('refused:', err.toString())
    return
  }
  await post('auth', 'user-id-auth', creds)
  log('authentication successful')
}
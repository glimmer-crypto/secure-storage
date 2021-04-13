const elliptic = require("elliptic")
const CBOR = require("cbor-js")

const ec = new elliptic.ec("p256")

const Buffer = {
  /**
   * @param { (Uint8Array | number[])[] } buffers
   * @returns { Uint8Array }
   */
  concat(...buffers) {
    let totalLength = 0
    for (let i = 0; i < buffers.length; i++) {
      const buffer = buffers[i]
      if (
        !(buffer instanceof Uint8Array) && !Array.isArray(buffer)
      ) throw new TypeError()

      totalLength += buffer.length
    }
  
    const returnBuffer = new Uint8Array(totalLength)
    let currentLength = 0
    for (let i = 0; i < buffers.length; i++) {
      const buffer = buffers[i]

      returnBuffer.set(buffer, currentLength)
      currentLength += buffer.length
    }
  
    return returnBuffer
  },

  /**
   * @param { Uint8Array | number[] } buf1
   * @param { Uint8Array | number[] } buf2
   * @returns { boolean }
   */
  equal(buf1, buf2) {
    if (
      !(buf1 instanceof Uint8Array) && !Array.isArray(buf1) ||
      !(buf2 instanceof Uint8Array) && !Array.isArray(buf2)
    ) throw new TypeError()

    if (buf1.length !== buf2.length) {
      return false
    }

    for (let i = 0; i < buf1.length; i++) {
      if (buf1[i] !== buf2[i]) {
        return false
      }
    }

    return true
  },

  /**
   * @param { Uint8Array | ArrayBuffer | number[] } buffer
   * @returns { string }
   */
  toString(buffer) {
    if (
      !(buffer instanceof Uint8Array) && !(buffer instanceof ArrayBuffer) && !Array.isArray(buffer)
    ) throw new TypeError()

    let arr = buffer
    if (!(arr instanceof Uint8Array)) arr = new Uint8Array(buffer)

    if (arr.length % 2 === 0) {
      arr = Buffer.concat([2, 0], arr)
    } else {
      arr = Buffer.concat([1], arr)
    }

    return String.fromCharCode.apply(null, new Uint16Array(arr.buffer))
  },

  /**
   * @param { string } str
   * @returns { Uint8Array }
   */
  fromString(str) {
    let arr = new Uint16Array(str.length)
    for (let i = 0; i < str.length; i++) {
      arr[i] = str.charCodeAt(i)
    }
    
    arr = new Uint8Array(arr.buffer)

    return arr.slice(arr[0])
  }
}

/**
 * @param { IDBRequest } request
 * @returns { Promise }
 */
function idbPromise(request) {
  return new Promise((resolve, reject) => {
    try {
      if (request.result) {
        resolve(request.result)
        return
      } else if (request.error) {
        reject(request.error)
        return
      }
    } catch { /* Request is still pending */ }
    

    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

const prv = {
  /** @type { IDBDatabase } */
  db: undefined,
  /** @type { CryptoKey } */
  symmetricKey: undefined,
  /** @type { ArrayBuffer } */
  rawKey: undefined,
  /** @type { Uint8Array } */
  pubKeyHash: undefined,
  /** @type { Uint8Array } */
  authId: undefined,

  async setup() {
    const open = indexedDB.open("_SecureStorage", 1)
    open.onupgradeneeded = () => {
      const database = open.result
      database.createObjectStore("internal", { keyPath: "key" })
      database.createObjectStore("secure", { keyPath: "key" })
    }

    /** @type { IDBDatabase } */
    const database = await idbPromise(open)
    prv.db = database

    const internalStore = database.transaction("internal", "readwrite").objectStore("internal")

    const storedId = await idbPromise(internalStore.get("authId"))
    const storedHash = await idbPromise(internalStore.get("pubKeyHash"))

    if (storedId) prv.authId = new Uint8Array(storedId.value)
    if (storedHash) prv.pubKeyHash = new Uint8Array(storedHash.value)

    let keyBuffer
    if (public.options.expiration === "session") {
      await idbPromise(internalStore.delete("encKey")) // Remove potentially stored data that doesn't match the desired expiration
      keyBuffer = sessionStorage.getItem("_SecureStorage")
      if (keyBuffer) keyBuffer = Buffer.fromString(keyBuffer).buffer
    } else if (public.options.expiration === "never") {
      keyBuffer = await idbPromise(internalStore.get("encKey"))
      if (keyBuffer) keyBuffer = keyBuffer.value
    }

    if (keyBuffer) {
      prv.symmetricKey = await crypto.subtle.importKey(
        "raw", keyBuffer, "AES-GCM", false, ["encrypt", "decrypt"]
      )

      public.state = "unlocked"
    } else {
      public.state = "locked"
    }
  },

  /**
   * @param { PublicKeyCredentialCreationOptions } creationOptions 
   */
  async createPublicKey(creationOptions) {
    const options = {
      publicKey: Object.assign({
        rp: { name: "Secure Storage" },
        user: {
          id: new ArrayBuffer(),
          name: "Secure Storage",
          displayName: "Secure Storage"
        }
      }, creationOptions)
    }
    if (!options.publicKey.challenge) options.publicKey.challenge = crypto.getRandomValues(new Uint8Array(32))
    options.publicKey.pubKeyCredParams = [ { type: "public-key", alg: -7 } ]
    options.publicKey.authenticatorSelection = { authenticatorAttachment: "platform" }

    const credential = await navigator.credentials.create(options)
    const { response } = credential

    const authId = credential.rawId
    prv.authId = authId

    const attestationObject = CBOR.decode(response.attestationObject)
    /** @type { Uint8Array } */
    const authData = attestationObject.authData

    const idLength = new DataView(authData.slice(53, 55).buffer).getInt16()
    const publicKeyData = CBOR.decode(authData.slice(55 + idLength).buffer)

    if (publicKeyData[3] !== -7 || publicKeyData[1] !== 2 || publicKeyData[-1] !== 1) {
      throw new Error("Unknown public key format")
    }

    const x = publicKeyData[-2]
    const y = publicKeyData[-3]

    const keyHash1 = await crypto.subtle.digest("SHA-256", Buffer.concat(x, y)) // Use first hash for encryption key
    const keyHash2 = await crypto.subtle.digest("SHA-256", keyHash1) // Store second hash

    const internalStore = prv.db.transaction("internal", "readwrite").objectStore("internal")
    internalStore.put({ key: "authId", value: authId })
    internalStore.put({ key: "pubKeyHash", value: keyHash2 })

    prv.symmetricKey = await crypto.subtle.importKey(
      "raw", keyHash1, "AES-GCM", false, ["encrypt", "decrypt"]
    )

    return {
      credential, rawKey: keyHash1
    }
  },

  /**
   * @param { PublicKeyCredentialRequestOptions } requestOptions
   */
  async getPublicKey(requestOptions) {
    const options = {
      publicKey: Object.assign({}, requestOptions)
    }
    if (!options.publicKey.challenge) options.publicKey.challenge = crypto.getRandomValues(new Uint8Array(32))
    options.publicKey.allowCredentials = [ { type: "public-key", id: prv.authId, transports: ["internal"] } ]

    const credential = await navigator.credentials.get(options)
    const response = credential.response
    const authData = new Uint8Array(response.authenticatorData)
    const signature = new Uint8Array(response.signature)

    const hashedClientJSON = new Uint8Array(await crypto.subtle.digest("SHA-256", response.clientDataJSON))
    const message = Buffer.concat(authData, hashedClientJSON)
    const messageDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", message))

    for (let i = 0; i < 4; i++) {
      let recoveredKey
      try {
        recoveredKey = ec.recoverPubKey(messageDigest, signature, i)
      } catch (err) {
        console.error(err)
        continue
      }

      const recoveredBuffer = recoveredKey.encode()
      const x = recoveredBuffer.slice(1, 33)
      const y = recoveredBuffer.slice(33)

      const keyHash1 = await crypto.subtle.digest("SHA-256", Buffer.concat(x, y))
      const keyHash2 = new Uint8Array(await crypto.subtle.digest("SHA-256", keyHash1))

      if (Buffer.equal(keyHash2, prv.pubKeyHash)) {
        prv.symmetricKey = await crypto.subtle.importKey(
          "raw", keyHash1, "AES-GCM", false, ["encrypt", "decrypt"]
        )

        return {
          credential, rawKey: keyHash1
        }
      }
    }

    throw new Error("Unable to recover the key")
  }
}

let setupPromiseResolution

class SecureStorage {
  constructor() {
    /** @type { "not ready" | "locked" | "unlocked" } */
    this.state = "not ready"

    this.options = {
      /** @type { "load" | "session" | "never" } */
      expiration: "session"
    }

    this.setup = new Promise(r => setupPromiseResolution = r)
  }

  /**
   * @param { PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions } options 
   */
  async unlock(options) {
    if (this.state === "not ready") {
      throw new Error('Unable to unlock in the "not ready" state')
    }

    if (this.state === "unlocked") return

    let result
    if (prv.authId && prv.pubKeyHash) {
      result = await prv.getPublicKey(options)
    } else {
      result = await prv.createPublicKey(options)
    }

    if (result.rawKey) {
      if (this.options.expiration === "session") {
        sessionStorage.setItem("_SecureStorage", Buffer.toString(result.rawKey))
      } else if (this.options.expiration === "never") {
        const internalStore = prv.db.transaction("internal", "readwrite").objectStore("internal")
        internalStore.put({ key: "encKey", value: result.rawKey })
      }
    }

    this.state = "unlocked"
    return result.credential
  }


  /**
   * @param { string } key
   */
  async getItem(key) {
    if (this.state !== "unlocked") {
      throw new Error("Storage not unlocked, call unlock()")
    }

    const secureStore = prv.db.transaction("secure", "readonly").objectStore("secure")
    const storedObject = await idbPromise(secureStore.get(key))
    if (!storedObject) { return null }
    const storedValue = new Uint8Array(storedObject.value)

    const iv = storedValue.slice(0, 12)
    const encrypted = storedValue.slice(12)

    const buffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, prv.symmetricKey, encrypted)
    return CBOR.decode(buffer)
  }

  /**
   * @param { string } key
   */
  async setItem(key, value) {
    if (this.state !== "unlocked") {
      throw new Error("Storage not unlocked, call unlock()")
    }

    const buffer = CBOR.encode(value)
    const iv = window.crypto.getRandomValues(new Uint8Array(12))

    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, prv.symmetricKey, buffer)
    const storedValue = Buffer.concat(iv, new Uint8Array(encrypted)).buffer

    const secureStore = prv.db.transaction("secure", "readwrite").objectStore("secure")
    await idbPromise(secureStore.put({ key, value: storedValue }))
  }

  /**
   * @param { string } key
   */
  async deleteItem(key) {
    if (this.state !== "unlocked") {
      throw new Error("Storage not unlocked, call unlock()")
    }

    const secureStore = prv.db.transaction("secure", "readwrite").objectStore("secure")

    try {
      await idbPromise(secureStore.delete(key))
      return true
    } catch {
      return false
    }
  }

  async lock() {
    try {
      const internalStore = prv.db.transaction("internal", "readwrite").objectStore("internal")
      internalStore.delete("encKey")
    } catch { /* Record didn't exist */ }
    sessionStorage.removeItem("_SecureStorage")

    this.state = "not ready"
    prv.authId = undefined
    prv.pubKeyHash = undefined
    prv.symmetricKey = undefined
    prv.db = undefined

    await prv.setup()
  }

  hasCredential() {
    if (prv.authId && prv.pubKeyHash) {
      return true
    }

    return false
  }

  async reset() {
    prv.db.close()
    const deletion = indexedDB.deleteDatabase("_SecureStorage")
    await idbPromise(deletion)
    console.log("Deleted", deletion)

    await this.lock()
  }
}

const public = new SecureStorage()

window.addEventListener("DOMContentLoaded", function() {
  prv.setup().then(setupPromiseResolution)
})

window.secureStorage = public

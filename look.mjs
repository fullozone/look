import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import grpc from '@grpc/grpc-js'
import protoLoader from '@grpc/proto-loader'
import nacl from 'tweetnacl'
import bs58 from 'bs58'
import Redis from 'ioredis'

const here = path.dirname(fileURLToPath(import.meta.url))
const protoDir = path.resolve(here, '../mev-protos')

const loaderOpts = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [protoDir]
}

const RECONNECT_MS = 1500
const CALL_TIMEOUT_MS = 10000
const BUNDLE_TTL_S = 86400

function loadServices () {
  const def = protoLoader.loadSync(['auth.proto', 'searcher.proto'], loaderOpts)
  const pkg = grpc.loadPackageDefinition(def)
  return { AuthService: pkg.auth.AuthService, SearcherService: pkg.searcher.SearcherService }
}

function call (client, method, req) {
  return new Promise((resolve, reject) => {
    const deadline = new Date(Date.now() + CALL_TIMEOUT_MS)
    client[method](req, { deadline }, (err, res) => err ? reject(err) : resolve(res))
  })
}

function tsToMs (ts) {
  return Number(ts.seconds) * 1000 + Math.floor((ts.nanos || 0) / 1e6)
}

function halfway (expiresAt) {
  const now = Date.now()
  return now + Math.max(0, expiresAt - now) / 2
}

export function keypairFromFile (file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
  return nacl.sign.keyPair.fromSecretKey(Uint8Array.from(raw))
}

export class BlockEngine {
  constructor ({ url, keypair, redis, prefix = 'jito' }) {
    this.keypair = keypair
    this.pubkey = Buffer.from(keypair.publicKey)
    this.pubkey58 = bs58.encode(this.pubkey)
    this.prefix = prefix
    this.redis = new Redis(redis)
    this.tokens = null
    this.closed = false
    this.stream = null

    const { AuthService, SearcherService } = loadServices()
    const ssl = grpc.credentials.createSsl()
    this.auth = new AuthService(url, ssl)

    const bearer = grpc.credentials.createFromMetadataGenerator((_, cb) => {
      this.accessToken().then(token => {
        const md = new grpc.Metadata()
        md.add('authorization', `Bearer ${token}`)
        cb(null, md)
      }, cb)
    })
    this.searcher = new SearcherService(url, grpc.credentials.combineChannelCredentials(ssl, bearer))
  }

  key (id) {
    return `${this.prefix}:bundle:${id}`
  }

  async accessToken () {
    if (this.tokens && Date.now() < this.tokens.refreshAt) return this.tokens.access
    if (this.tokens) {
      try {
        const res = await call(this.auth, 'RefreshAccessToken', { refresh_token: this.tokens.refresh })
        this.tokens.access = res.access_token.value
        this.tokens.expiresAt = tsToMs(res.access_token.expires_at_utc)
        this.tokens.refreshAt = halfway(this.tokens.expiresAt)
        return this.tokens.access
      } catch (err) {
        console.warn('refresh rejected, new challenge:', err.message)
      }
    }
    await this.handshake()
    return this.tokens.access
  }

  async handshake () {
    const { challenge } = await call(this.auth, 'GenerateAuthChallenge', { role: 'SEARCHER', pubkey: this.pubkey })
    const message = `${this.pubkey58}-${challenge}`
    const signature = nacl.sign.detached(Buffer.from(message, 'utf8'), this.keypair.secretKey)
    const res = await call(this.auth, 'GenerateAuthTokens', {
      challenge: message,
      client_pubkey: this.pubkey,
      signed_challenge: Buffer.from(signature)
    })
    this.tokens = {
      access: res.access_token.value,
      expiresAt: tsToMs(res.access_token.expires_at_utc),
      refreshAt: halfway(tsToMs(res.access_token.expires_at_utc)),
      refresh: res.refresh_token.value
    }
  }

  async tipAccounts () {
    const res = await call(this.searcher, 'GetTipAccounts', {})
    return res.accounts
  }

  async sendBundle (txs, tags = {}) {
    const packets = txs.map(data => ({ data, meta: { size: data.length } }))
    const res = await call(this.searcher, 'SendBundle', { bundle: { header: null, packets } })
    const key = this.key(res.uuid)
    await this.redis.multi()
      .hset(key, { status: 'sent', sent_at: Date.now(), txs: txs.length, ...tags })
      .expire(key, BUNDLE_TTL_S)
      .incr(`${this.prefix}:bundles:sent`)
      .exec()
    return res.uuid
  }

  watchResults () {
    if (this.closed) return
    const stream = this.searcher.SubscribeBundleResults({})
    stream.on('data', msg => {
      this.recordResult(msg).catch(err => console.error('failed to record bundle result:', err.message))
    })
    stream.on('error', err => console.error('grpc subscription errored:', err.message))
    stream.on('close', () => {
      if (!this.closed) setTimeout(() => this.watchResults(), RECONNECT_MS + Math.floor(Math.random() * 250))
    })
    this.stream = stream
  }

  async recordResult (msg) {
    const key = this.key(msg.bundle_id)
    const mine = await this.redis.exists(key)
    if (!mine) return
    const state = msg.result
    const fields = { status: state, updated_at: Date.now() }
    if (state === 'rejected') fields.reason = JSON.stringify(msg.rejected)
    if (state === 'dropped') fields.reason = msg.dropped.reason
    await this.redis.hset(key, fields)
    if (state === 'processed' || state === 'finalized') {
      const first = await this.redis.hsetnx(key, 'landed_at', Date.now())
      if (first) await this.redis.incr(`${this.prefix}:bundles:landed`)
    }
  }

  async landRate () {
    const [sent, landed] = await this.redis.mget(`${this.prefix}:bundles:sent`, `${this.prefix}:bundles:landed`)
    const s = Number(sent) || 0
    const l = Number(landed) || 0
    return { sent: s, landed: l, rate: s ? l / s : 0 }
  }

  async close () {
    this.closed = true
    if (this.stream) this.stream.cancel()
    this.auth.close()
    this.searcher.close()
    await this.redis.quit()
  }
}

import express from 'express'
import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'fs'
import pkg from 'bloom-filters'
import { blake3 } from '@noble/hashes/blake3'
import { utf8ToBytes } from '@noble/hashes/utils'

const { HyperLogLog, ScalableBloomFilter } = pkg

const PORT = 3000
const HLL_REGISTERS = 1024

mkdirSync('data/daily', { recursive: true })

const allTime = existsSync('data/allTime.json') ? HyperLogLog.fromJSON(JSON.parse(readFileSync('data/allTime.json', 'utf8'))) : new HyperLogLog(HLL_REGISTERS)
const seenAll = existsSync('data/seenAll.json') ? ScalableBloomFilter.fromJSON(JSON.parse(readFileSync('data/seenAll.json', 'utf8'))) : new ScalableBloomFilter()

const app = express()
app.use(express.json())
app.use(express.static('public'))

app.post('/ingest', (req, res) => {
    try {
        const { pub } = req.body
        if (!pub) return res.status(400).json({ error: 'Missing public key' })

        const known = seenAll.has(pub)
        seenAll.add(pub)
        customHllUpdate(allTime, pub)

        writeFileSync('data/allTime.json', JSON.stringify(allTime.saveAsJSON()))
        writeFileSync('data/seenAll.json', JSON.stringify(seenAll.saveAsJSON()))

        return res.json({ success: true, count: allTime.count(), known })
    } catch (err) {
        console.error('ingest error', err)
        return res.status(500).json({ error: 'internal' })
    }
})

app.get('/api/stats', (req, res) => res.json({ success: true, count: allTime.count() }))

app.listen(PORT, () => console.log(`Stats server running on http://localhost:${PORT}`))

function hashTo64BigInt(bytes) {
    let v = 0n
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(bytes[i])
    return v
}

function customHllUpdate(hll, element) {
    const bytes = typeof element === 'string' ? utf8ToBytes(element) : element
    const digest = blake3(bytes)
    const v = hashTo64BigInt(digest)

    const nbBits = BigInt(hll._nbBytesPerHash)
    const mask = (1n << nbBits) - 1n
    const registerIndex = Number(v & mask)

    const second = v >> nbBits
    const k = 64 - Number(nbBits)
    const secondBin = second.toString(2).padStart(k, '0')
    const idx = secondBin.indexOf('1')
    const rho = idx === -1 ? k : idx + 1

    hll._registers[registerIndex] = Math.max(hll._registers[registerIndex], rho)
}
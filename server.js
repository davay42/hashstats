import express from 'express'
import { writeFileSync, mkdirSync, existsSync, readFileSync, readdirSync } from 'fs'
import pkg from 'bloom-filters'
import { blake3 } from '@noble/hashes/blake3'
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils'
import { ed25519 } from '@noble/curves/ed25519'
import { bech32 } from '@scure/base'

const { HyperLogLog, ScalableBloomFilter } = pkg
const PORT = 3000
const HLL_REGISTERS = 1024
const NONCE_WINDOW_MS = 60000 // 1 minute window for replay protection

// Ensure directories exist
mkdirSync('data/daily', { recursive: true })
mkdirSync('data/weekly', { recursive: true })
mkdirSync('data/monthly', { recursive: true })

// Date helpers
const getDateKey = () => new Date().toISOString().split('T')[0]
const getWeekKey = (date = new Date()) => {
    const year = date.getFullYear()
    const start = new Date(year, 0, 1)
    const week = Math.ceil((((date - start) / 86400000) + start.getDay() + 1) / 7)
    return `${year}-W${String(week).padStart(2, '0')}`
}
const getMonthKey = (date = new Date()) => {
    const year = date.getFullYear()
    const month = String(date.getMonth() + 1).padStart(2, '0')
    return `${year}-${month}`
}

// Custom HLL update using blake3
function customHllUpdate(hll, element) {
    const bytes = typeof element === 'string' ? utf8ToBytes(element) : element
    const digest = blake3(bytes)

    let v = 0n
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(digest[i])

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

// Load/save helpers
const loadHLL = (path) => existsSync(path)
    ? HyperLogLog.fromJSON(JSON.parse(readFileSync(path, 'utf8')))
    : new HyperLogLog(HLL_REGISTERS)

const loadBloom = (path) => existsSync(path)
    ? ScalableBloomFilter.fromJSON(JSON.parse(readFileSync(path, 'utf8')))
    : new ScalableBloomFilter()

const saveHLL = (path, hll) => writeFileSync(path, JSON.stringify(hll.saveAsJSON()))
const saveBloom = (path, bloom) => writeFileSync(path, JSON.stringify(bloom.saveAsJSON()))

// Load global structures
const allHLL = loadHLL('data/all.hll.json')
const allBloom = loadBloom('data/all.bf.json')

// Nonce tracking for replay protection
const usedNonces = new Map() // nonce -> timestamp
setInterval(() => {
    const now = Date.now()
    for (const [nonce, timestamp] of usedNonces.entries()) {
        if (now - timestamp > NONCE_WINDOW_MS) usedNonces.delete(nonce)
    }
}, 30000) // Clean up every 30 seconds

// Daily structure management with new users tracking
function getDailyData(dateKey) {
    const path = `data/daily/${dateKey}.hll.json`
    if (existsSync(path)) {
        const data = JSON.parse(readFileSync(path, 'utf8'))
        return {
            hll: HyperLogLog.fromJSON(data.hll),
            newUsersHll: data.newUsersHll ? HyperLogLog.fromJSON(data.newUsersHll) : new HyperLogLog(HLL_REGISTERS)
        }
    }
    return {
        hll: new HyperLogLog(HLL_REGISTERS),
        newUsersHll: new HyperLogLog(HLL_REGISTERS)
    }
}

function saveDailyData(dateKey, data) {
    writeFileSync(`data/daily/${dateKey}.hll.json`, JSON.stringify({
        hll: data.hll.saveAsJSON(),
        newUsersHll: data.newUsersHll.saveAsJSON()
    }))
}

// Aggregate and save weekly/monthly backups
function updateAggregates(dateKey) {
    const date = new Date(dateKey)
    const weekKey = getWeekKey(date)
    const monthKey = getMonthKey(date)

    const dailyData = getDailyData(dateKey)

    // Update weekly aggregate
    const weekPath = `data/weekly/${weekKey}.hll.json`
    const weekHLL = loadHLL(weekPath)
    weekHLL.merge(dailyData.hll)
    saveHLL(weekPath, weekHLL)

    // Update monthly aggregate
    const monthPath = `data/monthly/${monthKey}.hll.json`
    const monthHLL = loadHLL(monthPath)
    monthHLL.merge(dailyData.hll)
    saveHLL(monthPath, monthHLL)
}

// Verify signature
function verifySignature(message, signature, publicKey) {
    try {
        // Decode bech32 signature and public key
        const sigDecoded = bech32.decode(signature, 999)
        const pkDecoded = bech32.decode(publicKey, 999)

        const sigBytes = new Uint8Array(bech32.fromWords(sigDecoded.words))
        const pkBytes = new Uint8Array(bech32.fromWords(pkDecoded.words))

        // Convert message to bytes (hashkeys signs raw message bytes for ed25519)
        const messageBytes = utf8ToBytes(message)

        // Verify ed25519 signature
        return ed25519.verify(sigBytes, messageBytes, pkBytes)
    } catch (err) {
        console.error('Signature verification error:', err)
        return false
    }
}

// Express app
const app = express()
app.use(express.json())
app.use(express.static('public'))

app.post('/ingest', (req, res) => {
    try {
        const { publicKey, timestamp, nonce, signature } = req.body

        // Validate inputs
        if (!publicKey || !timestamp || !nonce || !signature) {
            return res.status(400).json({ error: 'Missing required fields' })
        }

        // Check timestamp is recent (within 1 minute)
        const now = Date.now()
        const msgTime = parseInt(timestamp)
        if (Math.abs(now - msgTime) > NONCE_WINDOW_MS) {
            return res.status(400).json({ error: 'Timestamp too old or in future' })
        }

        // Check nonce hasn't been used
        if (usedNonces.has(nonce)) {
            return res.status(400).json({ error: 'Nonce already used (replay attack?)' })
        }

        // Verify signature
        const message = `${timestamp}:${nonce}`
        if (!verifySignature(message, signature, publicKey)) {
            return res.status(401).json({ error: 'Invalid signature' })
        }

        // Mark nonce as used
        usedNonces.set(nonce, now)

        // Hash the public key to use as user identifier
        const userHash = bytesToHex(blake3(utf8ToBytes(publicKey)))

        const dateKey = getDateKey()
        const dailyData = getDailyData(dateKey)

        // Check if new user globally
        const isNewUser = !allBloom.has(userHash)

        // Update all structures
        allBloom.add(userHash)
        customHllUpdate(allHLL, userHash)
        customHllUpdate(dailyData.hll, userHash)

        // Track new users in separate HLL
        if (isNewUser) {
            customHllUpdate(dailyData.newUsersHll, userHash)
        }

        // Save
        saveDailyData(dateKey, dailyData)
        saveHLL('data/all.hll.json', allHLL)
        saveBloom('data/all.bf.json', allBloom)

        // Update aggregates (async, non-blocking)
        setImmediate(() => updateAggregates(dateKey))

        return res.json({
            success: true,
            date: dateKey,
            newUser: isNewUser,
            dau: dailyData.hll.count()
        })
    } catch (err) {
        console.error('Ingest error:', err)
        return res.status(500).json({ error: 'internal' })
    }
})

app.get('/api/stats', (req, res) => {
    try {
        const files = readdirSync('data/daily')
            .filter(f => f.endsWith('.hll.json'))
            .sort()
            .reverse()

        // Recent daily data (last 30 days)
        const recentDays = files.slice(0, 30).map(file => {
            const dateKey = file.replace('.hll.json', '')
            const dailyData = getDailyData(dateKey)
            return {
                date: dateKey,
                dau: dailyData.hll.count(),
                newUsers: dailyData.newUsersHll.count()
            }
        })

        // WAU: merge up to last 7 days (or fewer if not enough data)
        const wauDays = Math.min(7, files.length)
        let wauHLL = null
        if (wauDays > 0) {
            files.slice(0, wauDays).forEach((file, idx) => {
                const dateKey = file.replace('.hll.json', '')
                const dailyData = getDailyData(dateKey)
                if (idx === 0) {
                    // Start with a copy of the first day's HLL
                    wauHLL = HyperLogLog.fromJSON(dailyData.hll.saveAsJSON())
                } else {
                    wauHLL.merge(dailyData.hll)
                }
            })
        }
        if (!wauHLL) wauHLL = new HyperLogLog(HLL_REGISTERS)

        // MAU: merge up to last 30 days (or fewer if not enough data)
        const mauDays = Math.min(30, files.length)
        let mauHLL = null
        if (mauDays > 0) {
            files.slice(0, mauDays).forEach((file, idx) => {
                const dateKey = file.replace('.hll.json', '')
                const dailyData = getDailyData(dateKey)
                if (idx === 0) {
                    // Start with a copy of the first day's HLL
                    mauHLL = HyperLogLog.fromJSON(dailyData.hll.saveAsJSON())
                } else {
                    mauHLL.merge(dailyData.hll)
                }
            })
        }
        if (!mauHLL) mauHLL = new HyperLogLog(HLL_REGISTERS)

        // Retention using inclusion-exclusion: |A ∩ B| = |A| + |B| - |A ∪ B|
        const calcRetention = (cohortIdx, returnIdx) => {
            if (files.length <= Math.max(cohortIdx, returnIdx)) return null

            const cohortDate = files[cohortIdx].replace('.hll.json', '')
            const returnDate = files[returnIdx].replace('.hll.json', '')

            const cohortData = getDailyData(cohortDate)
            const returnData = getDailyData(returnDate)

            const cohortSize = cohortData.hll.count()
            const returnSize = returnData.hll.count()

            const unionHLL = new HyperLogLog(HLL_REGISTERS)
            unionHLL.merge(cohortData.hll)
            unionHLL.merge(returnData.hll)
            const unionSize = unionHLL.count()

            const retained = Math.max(0, cohortSize + returnSize - unionSize)
            const rate = cohortSize > 0 ? (retained / cohortSize * 100) : 0

            return {
                cohortDate,
                returnDate,
                cohortSize: Math.round(cohortSize),
                returnedUsers: Math.round(retained),
                retentionRate: Math.round(rate * 100) / 100
            }
        }

        // Adaptive retention: use available data
        const retention = {
            d1: files.length >= 2 ? calcRetention(1, 0) : null,
            d7: files.length >= 2 ? calcRetention(Math.min(7, files.length - 1), 0) : null,
            d30: files.length >= 2 ? calcRetention(Math.min(30, files.length - 1), 0) : null
        }

        return res.json({
            success: true,
            allTime: allHLL.count(),
            wau: wauHLL.count(),
            mau: mauHLL.count(),
            recentDays,
            retention
        })
    } catch (err) {
        console.error('Stats error:', err)
        return res.status(500).json({ error: 'internal' })
    }
})

app.listen(PORT, () => console.log(`📊 Stats server running on http://localhost:${PORT}`))
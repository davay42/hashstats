import express from 'express'
import { writeFileSync, mkdirSync, existsSync, readFileSync, readdirSync } from 'fs'
import pkg from 'bloom-filters'
import { blake3 } from '@noble/hashes/blake3'
import { utf8ToBytes } from '@noble/hashes/utils'

const { HyperLogLog, ScalableBloomFilter } = pkg

const PORT = 3000
const HLL_REGISTERS = 1024

mkdirSync('data/daily', { recursive: true })

// Get today's date string (YYYY-MM-DD)
const getDateKey = () => new Date().toISOString().split('T')[0]

// Load or create daily structures
function getDailyStructures(dateKey) {
    const path = `data/daily/${dateKey}.json`
    if (existsSync(path)) {
        const data = JSON.parse(readFileSync(path, 'utf8'))
        return {
            hll: HyperLogLog.fromJSON(data.hll),
            bloom: ScalableBloomFilter.fromJSON(data.bloom),
            count: data.count
        }
    }
    return {
        hll: new HyperLogLog(HLL_REGISTERS),
        bloom: new ScalableBloomFilter(),
        count: 0
    }
}

// Save daily structures
function saveDailyStructures(dateKey, structures) {
    writeFileSync(`data/daily/${dateKey}.json`, JSON.stringify({
        hll: structures.hll.saveAsJSON(),
        bloom: structures.bloom.saveAsJSON(),
        count: structures.count
    }))
}

// Load all-time structures
const allTime = existsSync('data/allTime.json')
    ? HyperLogLog.fromJSON(JSON.parse(readFileSync('data/allTime.json', 'utf8')))
    : new HyperLogLog(HLL_REGISTERS)

const seenAll = existsSync('data/seenAll.json')
    ? ScalableBloomFilter.fromJSON(JSON.parse(readFileSync('data/seenAll.json', 'utf8')))
    : new ScalableBloomFilter()

const app = express()
app.use(express.json())
app.use(express.static('public'))

app.post('/ingest', (req, res) => {
    try {
        const { pub } = req.body
        if (!pub) return res.status(400).json({ error: 'Missing public key' })

        const dateKey = getDateKey()
        const daily = getDailyStructures(dateKey)

        // Check if user was seen before (globally and today)
        const knownGlobally = seenAll.has(pub)
        const knownToday = daily.bloom.has(pub)

        // Update structures
        seenAll.add(pub)
        daily.bloom.add(pub)
        customHllUpdate(allTime, pub)
        customHllUpdate(daily.hll, pub)

        if (!knownToday) daily.count++

        // Persist
        saveDailyStructures(dateKey, daily)
        writeFileSync('data/allTime.json', JSON.stringify(allTime.saveAsJSON()))
        writeFileSync('data/seenAll.json', JSON.stringify(seenAll.saveAsJSON()))

        return res.json({
            success: true,
            date: dateKey,
            newUser: !knownGlobally,
            dailyCount: daily.count
        })
    } catch (err) {
        console.error('ingest error', err)
        return res.status(500).json({ error: 'internal' })
    }
})

app.get('/api/stats', (req, res) => {
    try {
        const dateKey = getDateKey()
        const files = readdirSync('data/daily').filter(f => f.endsWith('.json')).sort().reverse()

        // Get recent daily data
        const recentDays = files.slice(0, 30).map(file => {
            const data = JSON.parse(readFileSync(`data/daily/${file}`, 'utf8'))
            return {
                date: file.replace('.json', ''),
                dau: data.count
            }
        })

        // Calculate WAU (last 7 days)
        const wauHll = new HyperLogLog(HLL_REGISTERS)
        files.slice(0, 7).forEach(file => {
            const data = JSON.parse(readFileSync(`data/daily/${file}`, 'utf8'))
            const dayHll = HyperLogLog.fromJSON(data.hll)
            wauHll.merge(dayHll)
        })

        // Calculate MAU (last 30 days)
        const mauHll = new HyperLogLog(HLL_REGISTERS)
        files.slice(0, 30).forEach(file => {
            const data = JSON.parse(readFileSync(`data/daily/${file}`, 'utf8'))
            const dayHll = HyperLogLog.fromJSON(data.hll)
            mauHll.merge(dayHll)
        })

        // Calculate retention metrics
        const retention = calculateRetention(files)

        return res.json({
            success: true,
            allTime: allTime.count(),
            wau: wauHll.count(),
            mau: mauHll.count(),
            recentDays,
            retention
        })
    } catch (err) {
        console.error('stats error', err)
        return res.status(500).json({ error: 'internal' })
    }
})

function calculateRetention(files) {
    const retention = { d1: null, d7: null, d30: null }

    // D1 Retention (yesterday's users who came back today)
    if (files.length >= 2) {
        retention.d1 = calculateRetentionRate(files[1], files[0])
    }

    // D7 Retention (7 days ago users who came back today)
    if (files.length >= 8) {
        retention.d7 = calculateRetentionRate(files[7], files[0])
    }

    // D30 Retention (30 days ago users who came back today)
    if (files.length >= 31) {
        retention.d30 = calculateRetentionRate(files[30], files[0])
    }

    return retention
}

function calculateRetentionRate(cohortFile, returnFile) {
    try {
        const cohortData = JSON.parse(readFileSync(`data/daily/${cohortFile}`, 'utf8'))
        const returnData = JSON.parse(readFileSync(`data/daily/${returnFile}`, 'utf8'))

        const cohortBloom = ScalableBloomFilter.fromJSON(cohortData.bloom)
        const returnBloom = ScalableBloomFilter.fromJSON(returnData.bloom)

        // Approximate: count how many from cohort returned
        // Note: This is an approximation since we can't iterate bloom filters perfectly
        // In production, you'd want to track cohorts more precisely

        return {
            cohortDate: cohortFile.replace('.json', ''),
            cohortSize: cohortData.count,
            returnDate: returnFile.replace('.json', ''),
            // For now, return null - proper implementation needs cohort tracking
            returnedUsers: null,
            note: "Bloom filters don't support perfect intersection - consider tracking cohorts separately"
        }
    } catch (err) {
        return null
    }
}

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
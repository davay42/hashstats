import express from 'express';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import Bloom from 'bloom-filters';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

const { HyperLogLog, BloomFilter } = Bloom

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Configuration
const PORT = 3000;
const SERVER_SECRET = hexToBytes(process.env.SERVER_SECRET || '0000000000000000000000000000000000000000000000000000000000000000');
const STORAGE_FILE = './stats.json';
const HLL_REGISTERS = 128;
const BLOOM_SIZE = 2048;
const BLOOM_HASHES = 4;
const TIMESTAMP_WINDOW = 120; // seconds

// In-memory storage
let stats = {
  daily: {},      // { 'YYYY-MM-DD': { hll, bloom } }
  allTime: null,  // global HLL
  seenAll: null   // global Bloom for new/returning detection
};

// Initialize structures
function initStorage() {
  if (!stats.allTime) {
    stats.allTime = new HyperLogLog(HLL_REGISTERS);
  }
  if (!stats.seenAll) {
    stats.seenAll = new BloomFilter(BLOOM_SIZE * 10, BLOOM_HASHES);
  }
}

function initDay(day) {
  if (!stats.daily[day]) {
    stats.daily[day] = {
      hll: new HyperLogLog(HLL_REGISTERS),
      bloom: new BloomFilter(BLOOM_SIZE, BLOOM_HASHES)
    };
  }
}

// Persistence helpers
function saveStats() {
  try {
    const serialized = {
      daily: Object.fromEntries(
        Object.entries(stats.daily).map(([day, data]) => [
          day,
          {
            hll: data.hll.saveAsJSON(),
            bloom: data.bloom.saveAsJSON()
          }
        ])
      ),
      allTime: stats.allTime.saveAsJSON(),
      seenAll: stats.seenAll.saveAsJSON()
    };
    writeFileSync(STORAGE_FILE, JSON.stringify(serialized, null, 2));
  } catch (err) {
    console.error('Save failed:', err);
  }
}

function loadStats() {
  try {
    if (existsSync(STORAGE_FILE)) {
      const data = JSON.parse(readFileSync(STORAGE_FILE, 'utf8'));

      stats.daily = Object.fromEntries(
        Object.entries(data.daily || {}).map(([day, serialized]) => [
          day,
          {
            hll: HyperLogLog.fromJSON(serialized.hll),
            bloom: BloomFilter.fromJSON(serialized.bloom)
          }
        ])
      );

      stats.allTime = data.allTime
        ? HyperLogLog.fromJSON(data.allTime)
        : new HyperLogLog(HLL_REGISTERS);

      stats.seenAll = data.seenAll
        ? BloomFilter.fromJSON(data.seenAll)
        : new BloomFilter(BLOOM_SIZE * 10, BLOOM_HASHES);

      console.log(`Loaded stats for ${Object.keys(stats.daily).length} days`);
    } else {
      initStorage();
    }
  } catch (err) {
    console.error('Load failed:', err);
    initStorage();
  }
}

// Utility functions
const today = () => new Date().toISOString().slice(0, 10);

function concatBytes(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function deriveStoredId(pubkeyHex) {
  // Use HMAC-SHA256 from Noble
  const pubkeyBytes = hexToBytes(pubkeyHex);
  const derived = hmac(sha256, SERVER_SECRET, pubkeyBytes);
  return bytesToHex(derived);
}

// POST /ingest - receive signed stats ping
app.post('/ingest', (req, res) => {
  try {
    const { pub, ts, nonce, sig } = req.body;

    if (!pub || !ts || !nonce || !sig) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // 1. Verify timestamp freshness
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > TIMESTAMP_WINDOW) {
      return res.status(400).json({ error: 'Timestamp outside valid window' });
    }

    // 2. Reconstruct message and verify signature
    const pubBytes = hexToBytes(pub);
    const sigBytes = hexToBytes(sig);
    const message = concatBytes(
      pubBytes,
      utf8ToBytes(ts.toString()),
      utf8ToBytes(nonce)
    );

    const valid = ed25519.verify(sigBytes, message, pubBytes);
    if (!valid) {
      return res.status(400).json({ error: 'Invalid signature' });
    }

    // 3. Derive anonymized ID using Noble HMAC
    const storedId = deriveStoredId(pub);
    const day = today();

    // 4. Update structures
    initDay(day);
    stats.daily[day].hll.update(storedId);
    stats.daily[day].bloom.add(storedId);
    stats.allTime.update(storedId);
    stats.seenAll.add(storedId);

    // 5. Persist (async, non-blocking)
    setImmediate(() => saveStats());

    res.json({ success: true, day });
  } catch (err) {
    console.error('Ingest error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/stats - serve aggregated metrics
app.get('/api/stats', (req, res) => {
  try {
    const days = Object.keys(stats.daily).sort();
    const result = {
      dau: {},
      wau: {},
      mau: {},
      total: stats.allTime.count()
    };

    days.forEach((day, idx) => {
      // DAU
      result.dau[day] = stats.daily[day].hll.count();

      // WAU - last 7 days
      const wauDays = days.slice(Math.max(0, idx - 6), idx + 1);
      const wauHLL = new HyperLogLog(HLL_REGISTERS);
      wauDays.forEach(d => wauHLL.merge(stats.daily[d].hll));
      result.wau[day] = wauHLL.count();

      // MAU - last 30 days
      const mauDays = days.slice(Math.max(0, idx - 29), idx + 1);
      const mauHLL = new HyperLogLog(HLL_REGISTERS);
      mauDays.forEach(d => mauHLL.merge(stats.daily[d].hll));
      result.mau[day] = mauHLL.count();
    });

    res.json(result);
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to compute stats' });
  }
});

// Initialize and start
loadStats();

app.listen(PORT, () => {
  console.log(`Stats server running on http://localhost:${PORT}`);
  console.log(`Total unique users: ${stats.allTime.count()}`);
});
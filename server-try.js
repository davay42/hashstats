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
// HyperLogLog config - 128 registers gives ~2% standard error for cardinalities > 10^9
const HLL_REGISTERS = 128;
// Remove these as we'll use BloomFilter.create() for optimal sizing
// const BLOOM_SIZE = 2048;
// const BLOOM_HASHES = 4;
const TIMESTAMP_WINDOW = 120; // seconds

// In-memory storage
let stats = {
  daily: {},      // { 'YYYY-MM-DD': { hll, bloom } }
  allTime: null,  // global HLL
  seenAll: null   // global Bloom for new/returning detection
};

// Initialize structures with optimal parameters
function initStorage() {
  if (!stats.allTime) {
    // Initialize HLL with more registers for better accuracy on large numbers
    // 128 registers gives ~2% standard error which is good for our use case
    stats.allTime = new HyperLogLog(HLL_REGISTERS);
    console.log(`All-time HLL accuracy: ${stats.allTime.accuracy()}`);
  }
  if (!stats.seenAll) {
    // Create Bloom filter optimized for expected items and error rate
    const expectedItems = 1000000; // Adjust based on your needs
    const errorRate = 0.01; // 1% false positive rate
    stats.seenAll = BloomFilter.create(expectedItems, errorRate);
    console.log(`All-time Bloom filter error rate: ${errorRate}`);
  }
}

function initDay(day) {
  if (!stats.daily[day]) {
    // Daily HLL same as all-time for consistency
    const hll = new HyperLogLog(HLL_REGISTERS);

    // Create daily Bloom filter with optimal parameters
    // Expect fewer items per day than all-time
    const expectedDailyItems = 10000; // Adjust based on your needs
    const dailyErrorRate = 0.01;
    const bloom = BloomFilter.create(expectedDailyItems, dailyErrorRate);

    stats.daily[day] = { hll, bloom };

    console.log(`Initialized day ${day}:
    - HLL accuracy: ${hll.accuracy()}
    - Bloom filter error rate: ${dailyErrorRate}`);
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
      console.log('Loading stats from file...');
      const data = JSON.parse(readFileSync(STORAGE_FILE, 'utf8'));

      stats.daily = Object.fromEntries(
        Object.entries(data.daily || {}).map(([day, serialized]) => {
          const hll = HyperLogLog.fromJSON(serialized.hll);
          const bloom = BloomFilter.fromJSON(serialized.bloom);
          console.log(`Loaded day ${day} - HLL count: ${hll.count()}, Bloom size: ${bloom._size}`);
          return [
            day,
            { hll, bloom }
          ];
        })
      );

      stats.allTime = data.allTime
        ? HyperLogLog.fromJSON(data.allTime)
        : new HyperLogLog(HLL_REGISTERS);

      stats.seenAll = data.seenAll
        ? BloomFilter.fromJSON(data.seenAll)
        : new BloomFilter(BLOOM_SIZE * 10, BLOOM_HASHES);

      console.log(`Loaded stats summary:
      - Total days: ${Object.keys(stats.daily).length}
      - All time unique users: ${stats.allTime.count()}
      - Bloom filter size: ${stats.seenAll._size}`);
    } else {
      initStorage();
    }
  } catch (err) {
    // HLL works best with string input for consistent hashing
    console.log(`Updating structures with ID: ${storedId}`);

    // First verify HLL works standalone
    const testHll = new HyperLogLog(HLL_REGISTERS);
    testHll.update(storedId);
    console.log(`Test HLL count after single update: ${testHll.count()}`);

    // Add a second value to verify counting works
    testHll.update('test-value');
    console.log(`Test HLL count after second update: ${testHll.count()}`);

    // Now update the real HLLs
    console.log('Updating daily HLL...');
    stats.daily[day].hll.update(storedId);

    // Log HLL state and actual count
    const dailyCount = stats.daily[day].hll.count();
    console.log(`Daily HLL count after update: ${dailyCount}`);
    console.log('Daily HLL internal state:', JSON.stringify(stats.daily[day].hll.saveAsJSON()));

    // Update Bloom filters with same buffer
    console.log('Updating daily Bloom...');
    stats.daily[day].bloom.add(idBuffer);

    console.log('Updating all-time HLL...');
    stats.allTime.update(idBuffer);
    const totalCount = stats.allTime.count();
    console.log(`All-time HLL count after update: ${totalCount}`);
    console.log('All-time HLL internal state:', JSON.stringify(stats.allTime.saveAsJSON()));

    console.log('Updating all-time Bloom...');
    stats.seenAll.add(idBuffer);

    console.log(`Stats after update:\n    - Daily HLL count: ${stats.daily[day].hll.count()}\n    - All time HLL count: ${stats.allTime.count()}\n    - Is in daily Bloom: ${stats.daily[day].bloom.has(storedIdBytes)}\n    - Is in all-time Bloom: ${stats.seenAll.has(storedIdBytes)}`);
    const pubkeyBytes = hexToBytes(pubkeyHex);
    const derived = hmac(sha256, SERVER_SECRET, pubkeyBytes);
    return bytesToHex(derived);
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
    console.log(`Processing stats for day ${day}, derived ID: ${storedId.slice(0, 8)}...`);

    // 4. Update structures
    initDay(day);
    console.log(`Current daily stats before update - HLL count: ${stats.daily[day].hll.count()}`);

    // Test direct HLL functionality with string inputs
    const testHll = new HyperLogLog(HLL_REGISTERS);
    console.log('Test update with storedId:', storedId);
    // Convert hex string to simpler format for better hashing
    const testStoredId = Buffer.from(storedId, 'hex').toString('base64');
    testHll.update(testStoredId);
    console.log(`Test HLL count with just stored ID: ${testHll.count()}`);

    // Verify HLL works with test data
    const testHll2 = new HyperLogLog(HLL_REGISTERS);
    testHll2.update('test-value-1');
    testHll2.update('test-value-2');
    console.log(`Test HLL2 count with test values: ${testHll2.count()}`);

    // Update actual structures with detailed logging
    console.log('Updating daily HLL...');
    console.log('Updating with storedId:', storedId);
    // Convert hex to base64 for better hash distribution
    const base64Id = Buffer.from(storedId, 'hex').toString('base64');
    stats.daily[day].hll.update(base64Id);
    const dailyCount = stats.daily[day].hll.count();
    console.log(`Daily HLL count after update: ${dailyCount}`);
    console.log('Daily HLL internal state:', JSON.stringify(stats.daily[day].hll.saveAsJSON()));

    console.log('Updating daily Bloom...');
    stats.daily[day].bloom.add(storedId);

    console.log('Updating all-time HLL...');
    // Use same base64 encoding for consistent hashing
    stats.allTime.update(base64Id);
    const totalCount = stats.allTime.count();
    console.log(`All-time HLL count after update: ${totalCount}`);
    console.log('All-time HLL internal state:', JSON.stringify(stats.allTime.saveAsJSON()));

    console.log('Updating all-time Bloom...');
    stats.seenAll.add(storedId);

    console.log(`Stats after update:
    - Daily HLL count: ${stats.daily[day].hll.count()}
    - All time HLL count: ${stats.allTime.count()}
    - Is in daily Bloom: ${stats.daily[day].bloom.has(storedId)}
    - Is in all-time Bloom: ${stats.seenAll.has(storedId)}`);    // 5. Persist (async, non-blocking)
    setImmediate(() => {
      saveStats();
      console.log('Stats saved to disk');
    });

    res.json({ success: true, day });
  } catch (err) {
    console.error('Ingest error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/stats - serve aggregated metrics
app.get('/api/stats', (req, res) => {
  try {
    console.log('Computing aggregated stats...');
    const days = Object.keys(stats.daily).sort();
    console.log(`Found ${days.length} days of data to process`);

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
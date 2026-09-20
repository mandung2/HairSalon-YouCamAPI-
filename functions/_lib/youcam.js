// Server-side helper for Perfect Corp's YouCam AI Hairstyle Generator API.
// Docs referenced: https://docs.perfectcorp.com/develop/quick_start_guide
//                  https://docs.perfectcorp.com/reference/ai_hairstyle
//                  https://docs.perfectcorp.com/reference/file
//
// This file only runs inside the Cloudflare Pages Function (server side).
// It must never be imported by, or its secrets exposed to, the browser bundle.

// No external crypto library: node-forge's RNG auto-detects a "Node-like"
// environment and calls require('crypto').randomBytes, which the Cloudflare
// Workers/Pages Functions runtime does not implement, crashing with
// "_crypto.randomBytes is not a function". Everything below uses only
// Web-standard APIs that the Workers runtime guarantees (atob/btoa, BigInt,
// crypto.getRandomValues, TextEncoder), verified against Node's own
// RSA_PKCS1_PADDING decrypt to confirm byte-for-byte correctness.

const AUTH_BASE = 'https://yce-api-01.perfectcorp.com';
const API_BASE = 'https://yce-api-01.makeupar.com';

// Cloudflare's env var UI (and copy/paste in general) very easily leaves a
// trailing newline/space on a pasted value, or the key gets pasted as a full
// PEM block instead of the raw base64 body. Both would silently corrupt the
// RSA encryption, so normalize defensively.
function normalizeClientId(raw) {
  return String(raw).trim();
}

function normalizePublicKeyBase64(raw) {
  return String(raw)
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}

function base64ToBytes(b64) {
  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes) {
  let binStr = '';
  for (let i = 0; i < bytes.length; i++) binStr += String.fromCharCode(bytes[i]);
  return btoa(binStr);
}

function bytesToBigInt(bytes) {
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex === '0x' ? '0x0' : hex);
}

function bigIntToBytes(bi, len) {
  let hex = bi.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  if (bytes.length < len) {
    const out = new Uint8Array(len);
    out.set(bytes, len - bytes.length);
    return out;
  }
  return bytes;
}

// Minimal DER reader — just enough to walk a SubjectPublicKeyInfo structure.
function derReadTLV(bytes, pos) {
  const tag = bytes[pos++];
  let len = bytes[pos++];
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    len = 0;
    for (let i = 0; i < numBytes; i++) len = (len << 8) | bytes[pos++];
  }
  const start = pos;
  const end = start + len;
  return { tag, start, end, next: end };
}

// "RSA X.509 format" could mean a bare SubjectPublicKeyInfo, or a full X.509
// certificate (which has a SubjectPublicKeyInfo nested a few SEQUENCEs deep
// inside its tbsCertificate). Rather than assume one fixed shape, recursively
// scan the DER tree for a BIT STRING whose payload itself decodes as
// RSAPublicKey ::= SEQUENCE { INTEGER modulus, INTEGER publicExponent } —
// that works for both shapes without needing to know which one was supplied.
function tryReadRsaPublicKeyFromBitString(der, bitstrTlv) {
  try {
    const inner = der.slice(bitstrTlv.start + 1, bitstrTlv.end); // skip "unused bits" byte
    const seq = derReadTLV(inner, 0);
    if (seq.tag !== 0x30 || seq.next !== inner.length) return null;
    const modulusTlv = derReadTLV(inner, seq.start);
    if (modulusTlv.tag !== 0x02) return null;
    const expTlv = derReadTLV(inner, modulusTlv.next);
    if (expTlv.tag !== 0x02 || expTlv.next !== seq.end) return null;
    let modulusBytes = inner.slice(modulusTlv.start, modulusTlv.end);
    if (modulusBytes[0] === 0x00) modulusBytes = modulusBytes.slice(1); // strip sign byte
    const expBytes = inner.slice(expTlv.start, expTlv.end);
    return { n: bytesToBigInt(modulusBytes), e: bytesToBigInt(expBytes), keyByteLen: modulusBytes.length };
  } catch (err) {
    return null;
  }
}

function findRsaPublicKeyInDer(der, pos, end) {
  while (pos < end) {
    let tlv;
    try {
      tlv = derReadTLV(der, pos);
    } catch (err) {
      return null;
    }
    if (tlv.tag === 0x03) {
      const found = tryReadRsaPublicKeyFromBitString(der, tlv);
      if (found) return found;
    }
    if (tlv.tag === 0x30 || tlv.tag === 0x31 || tlv.tag === 0xa0 || tlv.tag === 0xa3) {
      const found = findRsaPublicKeyInDer(der, tlv.start, tlv.end);
      if (found) return found;
    }
    pos = tlv.next;
  }
  return null;
}

function parseRsaPublicKeyFromX509Der(der) {
  const found = findRsaPublicKeyInDer(der, 0, der.length);
  if (!found) throw new Error('Could not find an RSA public key inside YOUCAM_CLIENT_SECRET');
  return found;
}

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// EME-PKCS1-v1_5 padding: 0x00 0x02 <non-zero random padding> 0x00 <message>
function pkcs1Pad(messageBytes, keyByteLen) {
  const psLen = keyByteLen - messageBytes.length - 3;
  if (psLen < 8) throw new Error('id_token message too long for the RSA key size');
  const ps = new Uint8Array(psLen);
  crypto.getRandomValues(ps);
  for (let i = 0; i < ps.length; i++) {
    while (ps[i] === 0) {
      const one = new Uint8Array(1);
      crypto.getRandomValues(one);
      ps[i] = one[0];
    }
  }
  const eb = new Uint8Array(keyByteLen);
  eb[0] = 0x00;
  eb[1] = 0x02;
  eb.set(ps, 2);
  eb[2 + psLen] = 0x00;
  eb.set(messageBytes, 3 + psLen);
  return eb;
}

function rsaPkcs1v15EncryptWithX509(messageStr, x509Base64) {
  const der = base64ToBytes(x509Base64);
  const { n, e, keyByteLen } = parseRsaPublicKeyFromX509Der(der);
  const padded = pkcs1Pad(new TextEncoder().encode(messageStr), keyByteLen);
  const cipherInt = modPow(bytesToBigInt(padded), e, n);
  return bytesToBase64(bigIntToBytes(cipherInt, keyByteLen));
}

function buildIdToken(clientId, clientSecretBase64X509) {
  const timestamp = Date.now();
  const message = `client_id=${clientId}&timestamp=${timestamp}`;
  return rsaPkcs1v15EncryptWithX509(message, clientSecretBase64X509);
}

function pick(obj, ...paths) {
  for (const path of paths) {
    const value = path.split('.').reduce((o, k) => (o == null ? o : o[k]), obj);
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

export async function getAccessToken(env) {
  const rawClientId = env.YOUCAM_CLIENT_ID;
  const rawClientSecret = env.YOUCAM_CLIENT_SECRET;
  if (!rawClientId || !rawClientSecret) {
    throw new Error('YOUCAM_CLIENT_ID / YOUCAM_CLIENT_SECRET is not configured');
  }

  const clientId = normalizeClientId(rawClientId);
  const clientSecret = normalizePublicKeyBase64(rawClientSecret);
  const idToken = buildIdToken(clientId, clientSecret);

  const res = await fetch(`${AUTH_BASE}/s2s/v1.0/client/auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: clientId, id_token: idToken })
  });

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(`YouCam auth failed (${res.status}): ${JSON.stringify(data)}`);
  }

  const accessToken = pick(data, 'result.access_token', 'data.access_token', 'access_token');
  if (!accessToken) {
    throw new Error(`YouCam auth response missing access_token: ${JSON.stringify(data)}`);
  }
  return accessToken;
}

// Step 2-3 of the documented flow: register the file, then PUT the raw
// bytes to the presigned URL the API gives back.
export async function uploadImage(accessToken, bytes, contentType, fileName) {
  const initRes = await fetch(`${API_BASE}/s2s/v2.0/file`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      files: [{ content_type: contentType, file_name: fileName, file_size: bytes.byteLength }]
    })
  });

  const initData = await initRes.json().catch(() => null);
  if (!initRes.ok) {
    throw new Error(`YouCam file init failed (${initRes.status}): ${JSON.stringify(initData)}`);
  }

  // Real response shape: { data: { files: [ { file_id, requests: [ { method, url, headers } ] } ] } }
  const fileEntry = pick(initData, 'data.files.0', 'result.files.0');
  const fileId = fileEntry && fileEntry.file_id;
  const uploadRequest = pick(fileEntry, 'requests.0');
  const uploadUrl = uploadRequest && uploadRequest.url;
  const uploadHeaders = (uploadRequest && uploadRequest.headers) || { 'Content-Type': contentType };

  if (!fileId || !uploadUrl) {
    throw new Error(`YouCam file init response missing file_id/url: ${JSON.stringify(initData)}`);
  }

  const putRes = await fetch(uploadUrl, {
    method: 'PUT',
    headers: uploadHeaders,
    body: bytes
  });
  if (!putRes.ok) {
    throw new Error(`YouCam file upload PUT failed (${putRes.status})`);
  }

  return fileId;
}

// Step 5 of the documented flow: create the hair-transfer task from the two
// uploaded file ids (the user's photo + the reference hairstyle photo).
export async function createHairTransferTask(accessToken, srcFileId, refFileId) {
  const res = await fetch(`${API_BASE}/s2s/v2.1/task/hair-transfer`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ src_file_id: srcFileId, ref_file_id: refFileId })
  });

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(`YouCam task create failed (${res.status}): ${JSON.stringify(data)}`);
  }

  const taskId = pick(data, 'data.task_id', 'result.task_id', 'task_id');
  if (!taskId) {
    throw new Error(`YouCam task create response missing task_id: ${JSON.stringify(data)}`);
  }
  return taskId;
}

// Step 6-7 of the documented flow: poll until task_status is success/error.
export async function pollHairTransferTask(accessToken, taskId, options = {}) {
  const maxAttempts = options.maxAttempts || 12;
  const intervalMs = options.intervalMs || 1500;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const res = await fetch(`${API_BASE}/s2s/v2.1/task/hair-transfer/${taskId}`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      throw new Error(`YouCam task status check failed (${res.status}): ${JSON.stringify(data)}`);
    }

    const status = pick(data, 'data.task_status', 'result.task_status');
    if (status === 'success') {
      const url = pick(data, 'data.results.url', 'result.results.url');
      if (!url) throw new Error(`YouCam task succeeded but result url missing: ${JSON.stringify(data)}`);
      return url;
    }
    if (status === 'error') {
      const errInfo = pick(data, 'data.error', 'result.error');
      throw new Error(`YouCam task failed: ${JSON.stringify(errInfo)}`);
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  throw new Error('YouCam task timed out while polling for a result');
}

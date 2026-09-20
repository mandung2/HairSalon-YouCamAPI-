// Server-side helper for Perfect Corp's YouCam AI Hairstyle Generator API.
// Docs referenced: https://docs.perfectcorp.com/develop/quick_start_guide
//                  https://docs.perfectcorp.com/reference/ai_hairstyle
//                  https://docs.perfectcorp.com/reference/file
//
// This file only runs inside the Cloudflare Pages Function (server side).
// It must never be imported by, or its secrets exposed to, the browser bundle.

import forge from 'node-forge';

const AUTH_BASE = 'https://yce-api-01.perfectcorp.com';
const API_BASE = 'https://yce-api-01.makeupar.com';

// Step 1 of the documented flow: build the RSA-encrypted id_token.
// Docs describe this as: "Encrypted client_id=<client_id>&timestamp=<ms> with
// RSA X.509 format Base64 encoded client_secret". The exact padding scheme
// (PKCS1 v1.5) is the common default Perfect Corp's sample SDKs use; if the
// auth call below ever returns 401, this is the first thing to re-check
// against the real code sample shown in your Perfect Corp console.
// Cloudflare's env var UI (and copy/paste in general) very easily leaves a
// trailing newline/space on a pasted value, or the key gets pasted as a full
// PEM block instead of the raw base64 body. Both silently corrupt the RSA
// encryption without throwing, and the API then answers with a generic
// "Invalid client_id or invalid id_token" 401. Normalize defensively.
function normalizeClientId(raw) {
  return String(raw).trim();
}

function normalizePublicKeyBase64(raw) {
  return String(raw)
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}

function buildIdToken(clientId, clientSecretBase64X509) {
  const timestamp = Date.now();
  const message = `client_id=${clientId}&timestamp=${timestamp}`;
  const der = forge.util.decode64(clientSecretBase64X509);
  const publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(der));
  const encrypted = publicKey.encrypt(message, 'RSAES-PKCS1-V1_5');
  return forge.util.encode64(encrypted);
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

  const fileId = pick(initData, 'data.file_id', 'result.file_id');
  const fileEntry = pick(initData, 'data.files.0', 'result.files.0');
  const uploadUrl = fileEntry && fileEntry.requests && fileEntry.requests.url;
  const uploadHeaders = (fileEntry && fileEntry.requests && fileEntry.requests.headers) || {
    'Content-Type': contentType
  };

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

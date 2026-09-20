// Cloudflare Pages Function: POST /api/hairstyle
//
// Receives the two photos from the browser (multipart/form-data: "src" =
// the customer's own photo, "ref" = the reference hairstyle photo), then
// drives the whole YouCam AI Hairstyle Generator flow server-side so the
// YOUCAM_CLIENT_SECRET never has to leave this function.

import { getAccessToken, uploadImage, createHairTransferTask, pollHairTransferTask } from '../_lib/youcam.js';

const MAX_BYTES = 10 * 1024 * 1024; // matches YouCam's 10MB per-image limit

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.YOUCAM_CLIENT_ID || !env.YOUCAM_CLIENT_SECRET) {
      return json(
        { ok: false, error: 'YOUCAM_CLIENT_ID / YOUCAM_CLIENT_SECRET 환경변수가 Cloudflare에 설정되어 있지 않습니다.' },
        500
      );
    }

    const form = await request.formData();
    const srcFile = form.get('src');
    const refFile = form.get('ref');

    if (!srcFile || typeof srcFile === 'string' || !refFile || typeof refFile === 'string') {
      return json({ ok: false, error: '내 사진과 원하는 헤어스타일 사진을 모두 업로드해주세요.' }, 400);
    }
    if (srcFile.size > MAX_BYTES || refFile.size > MAX_BYTES) {
      return json({ ok: false, error: '사진 용량은 각각 10MB 이하만 가능합니다.' }, 400);
    }

    const accessToken = await getAccessToken(env);

    const [srcBytes, refBytes] = await Promise.all([srcFile.arrayBuffer(), refFile.arrayBuffer()]);

    const [srcFileId, refFileId] = await Promise.all([
      uploadImage(accessToken, srcBytes, srcFile.type || 'image/jpeg', srcFile.name || 'src.jpg'),
      uploadImage(accessToken, refBytes, refFile.type || 'image/jpeg', refFile.name || 'ref.jpg')
    ]);

    const taskId = await createHairTransferTask(accessToken, srcFileId, refFileId);
    const resultUrl = await pollHairTransferTask(accessToken, taskId);

    return json({ ok: true, resultUrl });
  } catch (err) {
    return json({ ok: false, error: err && err.message ? err.message : String(err) }, 502);
  }
}

export async function onRequestGet() {
  return json({ ok: false, error: 'POST 요청만 지원합니다.' }, 405);
}

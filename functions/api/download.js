// Cloudflare Pages Function: GET /api/download?url=<encoded YouCam result URL>
//
// The AI result URL from YouCam is a temporary S3 presigned link. Browsers
// often ignore the `download` attribute on cross-origin links, so this
// fetches the image server-side (no CORS involved between servers) and
// re-serves it with Content-Disposition: attachment so the browser always
// offers a real "Save As" instead of just opening the image.
//
// Only S3 URLs are allowed through, so this can't be used as an open proxy
// for arbitrary URLs.

const ALLOWED_HOST_SUFFIXES = ['.amazonaws.com'];

function isAllowedUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') return false;
    return ALLOWED_HOST_SUFFIXES.some((suffix) => parsed.hostname.endsWith(suffix));
  } catch (err) {
    return false;
  }
}

export async function onRequestGet({ request }) {
  const requestUrl = new URL(request.url);
  const target = requestUrl.searchParams.get('url');

  if (!target || !isAllowedUrl(target)) {
    return new Response('Invalid or disallowed url', { status: 400 });
  }

  const upstream = await fetch(target);
  if (!upstream.ok || !upstream.body) {
    return new Response('Could not fetch the result image', { status: 502 });
  }

  const contentType = upstream.headers.get('Content-Type') || 'image/jpeg';
  const extension = contentType.includes('png') ? 'png' : 'jpg';

  return new Response(upstream.body, {
    status: 200,
    headers: {
      'Content-Type': contentType,
      'Content-Disposition': `attachment; filename="mandung2-ai-hairstyle.${extension}"`,
      'Cache-Control': 'no-store'
    }
  });
}

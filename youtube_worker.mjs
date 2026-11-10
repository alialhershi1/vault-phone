import { Innertube, Platform } from 'youtubei.js/web';
import { createWriteStream } from 'node:fs';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { basename } from 'node:path';

function cookieHeader() {
  const raw = (process.env.YT_COOKIES || process.env.YOUTUBE_COOKIES || '').trim();
  if (!raw) return '';
  const lines = raw.replace(/\r/g, '').split('\n');
  const rows = lines.filter((line) => line && (!line.trimStart().startsWith('#') || line.trimStart().startsWith('#HttpOnly_')));
  const netscape = rows.length > 0 && rows.every((line) => line.split('\t').length >= 7);
  if (netscape) {
    const pairs = [];
    for (const line of rows) {
      const fields = line.split('\t');
      const domain = fields[0].replace(/^#HttpOnly_/, '').toLowerCase();
      const name = fields[5];
      const value = fields.slice(6).join('\t');
      if ((domain === 'youtube.com' || domain.endsWith('.youtube.com') ||
           domain === 'google.com' || domain.endsWith('.google.com')) && name && value) {
        pairs.push(name + '=' + value);
      }
    }
    return [...new Set(pairs)].join('; ');
  }
  return raw
    .replace(/^\s*cookie\s*:\s*/i, '')
    .split(/[\r\n]+/)
    .join('; ')
    .trim();
}

async function main() {
  const url = process.argv[2];
  const outputPath = process.argv[3];
  if (!url || !outputPath) throw new Error('Missing video URL or output path.');
  const parsed = new URL(url);
  const videoId = parsed.searchParams.get('v') ||
    (parsed.hostname === 'youtu.be' ? parsed.pathname.split('/').filter(Boolean)[0] : '');
  if (!videoId || !/^[A-Za-z0-9_-]{11}$/.test(videoId)) {
    throw new Error('The YouTube video URL is not valid.');
  }

  // YouTube.js documents this interpreter hook for deciphering streaming formats.
  Platform.shim.eval = async (data) => new Function(data.output)();

  const cookie = cookieHeader();
  const yt = await Innertube.create({
    ...(cookie ? { cookie } : {}),
    client_type: 'WEB',
    retrieve_player: true,
    enable_session_cache: true
  });

  const info = await yt.getInfo(videoId);
  const title = info.basic_info?.title || info.title || 'YouTube video';
  const stream = await info.download({
    type: 'video+audio',
    quality: 'best',
    format: 'mp4'
  });

  let total = 0;
  const limit = new Transform({
    transform(chunk, encoding, callback) {
      total += chunk.length;
      if (total > 500 * 1024 * 1024) {
        callback(new Error('The video exceeds the 500 MB Vault Leech limit.'));
        return;
      }
      callback(null, chunk);
    }
  });
  await pipeline(Readable.fromWeb(stream), limit, createWriteStream(outputPath));
  process.stdout.write(JSON.stringify({ ok: true, title, id: videoId, bytes: total }) + '\n');
}

main().catch((error) => {
  const message = String(error?.message || error || 'YouTube.js download failed.')
    .replace(/[\r\n]+/g, ' ')
    .slice(0, 500);
  process.stdout.write(JSON.stringify({ ok: false, error: message }) + '\n');
  process.exitCode = 1;
});

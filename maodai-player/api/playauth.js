// Vercel Serverless Function
// GET /api/playauth?vid=xxxxxx
import crypto from "crypto";

function percentEncode(str = "") {
  return encodeURIComponent(str)
    .replace(/\!/g, "%21")
    .replace(/\'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A");
}

function buildCanonicalizedQuery(params) {
  const sorted = Object.keys(params).sort();
  return sorted.map(k => `${percentEncode(k)}=${percentEncode(params[k])}`).join("&");
}

function hmacSha1(key, str) {
  return crypto.createHmac("sha1", key).update(str).digest("base64");
}

export default async function handler(req, res) {
  try {
    const vid = (req.query.vid || "").trim();
    if (!vid) return res.status(400).json({ error: "Missing vid" });

    const AccessKeyId = process.env.ALIYUN_AK_ID;
    const AccessKeySecret = process.env.ALIYUN_AK_SECRET;
    const RegionId = process.env.ALIYUN_REGION || "cn-shanghai"; // 华东2(上海)

    if (!AccessKeyId || !AccessKeySecret) {
      return res.status(500).json({ error: "Missing Aliyun credentials in env" });
    }

    // GetVideoPlayAuth (VOD 2017-03-21)
    const params = {
      Action: "GetVideoPlayAuth",
      VideoId: vid,
      RegionId,
      Format: "JSON",
      Version: "2017-03-21",
      AccessKeyId,
      SignatureMethod: "HMAC-SHA1",
      Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      SignatureVersion: "1.0",
      SignatureNonce: crypto.randomUUID()
    };

    const canonicalizedQuery = buildCanonicalizedQuery(params);
    const stringToSign = `GET&%2F&${percentEncode(canonicalizedQuery)}`;
    const signature = hmacSha1(`${AccessKeySecret}&`, stringToSign);

    const url = `https://vod.${RegionId}.aliyuncs.com/?Signature=${percentEncode(signature)}&${canonicalizedQuery}`;

    const r = await fetch(url);
    const data = await r.json();

    if (!r.ok || data?.Code) {
      return res.status(500).json({ error: "Aliyun API error", detail: data });
    }

    // 只返回 playauth（不要把其他字段透给前端）
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({ playauth: data.PlayAuth });
  } catch (e) {
    return res.status(500).json({ error: "Server error", detail: String(e) });
  }
}


export async function analyzeFile(file) {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);

  const hex = [...bytes.slice(0, 16)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join(" ");

  const text = new TextDecoder().decode(
    bytes.slice(0, 100000)
  );

  const signature = bytes.slice(0, 8);
  let type = "Unknown";
  let category = "غير معروف";

  if (bytes[0] === 0x4D && bytes[1] === 0x5A) {
    type = "Windows PE";
    category = "ملف تنفيذي Windows";
  } else if (
    signature[0] === 0x50 &&
    signature[1] === 0x4B
  ) {
    type = "ZIP / APK";
    category = "أرشيف أو تطبيق Android محتمل";
  } else if (
    signature[0] === 0x7F &&
    signature[1] === 0x45 &&
    signature[2] === 0x4C &&
    signature[3] === 0x46
  ) {
    type = "ELF";
    category = "ملف Linux تنفيذي";
  } else if (
    signature[0] === 0x89 &&
    signature[1] === 0x50 &&
    signature[2] === 0x4E &&
    signature[3] === 0x47
  ) {
    type = "PNG";
    category = "صورة";
  } else if (
    signature[0] === 0x25 &&
    signature[1] === 0x50 &&
    signature[2] === 0x44 &&
    signature[3] === 0x46
  ) {
    type = "PDF";
    category = "مستند PDF";
  }

  const digest = await crypto.subtle.digest(
    "SHA-256",
    buffer
  );

  const sha256 = [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    name: file.name,
    size: file.size,
    type,
    category,
    mime: file.type || "Unknown",
    sha256,
    signature: hex,
    scannedAt: new Date().toISOString(),
    bytesScanned: bytes.length,
    preview: text.slice(0, 500)
  };
}

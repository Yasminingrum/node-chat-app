#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════╗
 * ║         SECURE CHAT — LAUNCHER               ║
 * ║  Pilih versi aplikasi yang ingin dijalankan  ║
 * ╚══════════════════════════════════════════════╝
 */

const { spawn } = require("child_process");
const readline = require("readline");
const path = require("path");
const fs = require("fs");

// ── Definisi versi ────────────────────────────────────────────────────────────
const VERSIONS = {
  a: {
    label: "Base Chat",
    folder: "a-base",
    description: "Chat dasar tanpa keamanan. Pesan dikirim plaintext.",
    features: ["✓ Koneksi client-server", "✓ Broadcast pesan", "✗ Tidak ada keamanan"],
    files: { server: "server.js", client: "client.js" },
  },
  b: {
    label: "Hash Detection",
    folder: "b-hash",
    description: "Deteksi modifikasi pesan oleh server menggunakan SHA-256.",
    features: ["✓ Semua fitur Base", "✓ Hash SHA-256", "✓ Deteksi server jahat (malicious-server.js)"],
    files: { server: "server.js", client: "client.js", extra: "malicious-server.js" },
  },
  c: {
    label: "Digital Signature",
    folder: "c-signature",
    description: "Deteksi impersonasi user menggunakan RSA Digital Signature.",
    features: ["✓ Semua fitur Hash", "✓ RSA Key Pair per user", "✓ Deteksi impersonasi (!impersonate)"],
    files: { server: "server.js", client: "client.js" },
  },
  d: {
    label: "Encryption",
    folder: "d-encryption",
    description: "Enkripsi pesan end-to-end menggunakan RSA-OAEP.",
    features: ["✓ Semua fitur Signature", "✓ Enkripsi RSA-OAEP", "✓ Secret chat (!secret <user>)", "✓ User lain hanya lihat ciphertext"],
    files: { server: "server.js", client: "client.js" },
  },
};

// ── Tampilkan menu ────────────────────────────────────────────────────────────
function showMenu() {
  console.clear();
  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║            SECURE CHAT APP — LAUNCHER               ║");
  console.log("╠══════════════════════════════════════════════════════╣");
  console.log("║  Pilih versi:                                        ║");
  console.log("╠══════════════════════════════════════════════════════╣");

  for (const [key, v] of Object.entries(VERSIONS)) {
    const folderExists = fs.existsSync(path.join(__dirname, v.folder));
    const status = folderExists ? "✓" : "✗ (folder tidak ada)";
    console.log(`║  [${key}] ${v.label.padEnd(20)} ${status.padEnd(22)}║`);
    console.log(`║      ${v.description.slice(0, 46).padEnd(46)}  ║`);
    console.log("║                                                      ║");
  }

  console.log("╠══════════════════════════════════════════════════════╣");
  console.log("║  Ketik: a / b / c / d  lalu tekan Enter              ║");
  console.log("║  Tambahkan 'server' atau 'client' untuk langsung run  ║");
  console.log("║  Contoh: b server   atau   d client                  ║");
  console.log("╚══════════════════════════════════════════════════════╝");
  console.log("");
}

// ── Tampilkan detail versi ────────────────────────────────────────────────────
function showDetail(key) {
  const v = VERSIONS[key];
  console.log(`\n┌─ [${key.toUpperCase()}] ${v.label} ${"─".repeat(40 - v.label.length)}`);
  console.log(`│  Folder : ./${v.folder}/`);
  console.log(`│  Fitur  :`);
  v.features.forEach((f) => console.log(`│    ${f}`));
  console.log(`│`);

  if (key === "a") {
    console.log(`│  Commands: (tidak ada command khusus)`);
    console.log(`│    Ketik pesan langsung lalu Enter untuk mengirim`);
    console.log(`│`);
  }
  if (key === "b") {
    console.log(`│  Commands: (tidak ada command khusus)`);
    console.log(`│    Ketik pesan langsung lalu Enter untuk mengirim`);
    console.log(`│`);
    console.log(`│  Pilihan server:`);
    console.log(`│    [server]   server.js          → server normal (aman)`);
    console.log(`│    [malicious] malicious-server.js → server jahat (+sus?)`);
    console.log(`│`);
    console.log(`│  Cara test:`);
    console.log(`│    1. Jalankan salah satu server di atas`);
    console.log(`│    2. Jalankan 2 client di terminal berbeda`);
    console.log(`│    3. Kirim pesan — jika malicious, client akan WARNING`);
    console.log(`│`);
  }
  if (key === "c") {
    console.log(`│  Commands:`);
    console.log(`│    !impersonate <username>  →  pura-pura jadi user lain`);
    console.log(`│    !exit                   →  kembali ke identitas asli`);
    console.log(`│`);
    console.log(`│  Cara test: ketik !impersonate Alice di terminal Eve,`);
    console.log(`│    lalu kirim pesan → client lain akan dapat WARNING`);
    console.log(`│`);
  }
  if (key === "d") {
    console.log(`│  Commands:`);
    console.log(`│    !secret <username>  →  mulai secret chat ke user tsb`);
    console.log(`│    !exit              →  keluar dari mode secret chat`);
    console.log(`│`);
    console.log(`│  Cara test: ketik !secret Bob, lalu kirim pesan`);
    console.log(`│    → Bob bisa baca plaintext, user lain hanya lihat ciphertext`);
    console.log(`│`);
  }

  console.log(`│  Jalankan:`);
  console.log(`│    node ${v.folder}/server.js`);
  console.log(`│    node ${v.folder}/client.js  (terminal baru, bisa banyak)`);
  console.log(`└${"─".repeat(46)}`);
}

// ── Jalankan file ─────────────────────────────────────────────────────────────
function runFile(key, role) {
  const v = VERSIONS[key];
  const folder = path.join(__dirname, v.folder);

  if (!fs.existsSync(folder)) {
    console.log(`\n❌ Folder "${v.folder}" tidak ditemukan!`);
    console.log(`   Buat dulu folder tersebut dengan file server.js dan client.js.`);
    return false;
  }

  let filename;
  if (role === "server") filename = v.files.server;
  else if (role === "client") filename = v.files.client;
  else if (role === "malicious") filename = v.files.extra;
  else {
    console.log(`\n❌ Role tidak dikenal: "${role}". Gunakan: server / client`);
    return false;
  }

  if (!filename) {
    console.log(`\n❌ File "${role}" tidak tersedia untuk versi ${key.toUpperCase()}.`);
    return false;
  }

  const filepath = path.join(folder, filename);
  if (!fs.existsSync(filepath)) {
    console.log(`\n❌ File tidak ditemukan: ${v.folder}/${filename}`);
    return false;
  }

  console.log(`\n▶ Menjalankan: ${v.folder}/${filename}`);
  console.log(`  (Tekan Ctrl+C untuk berhenti)\n`);
  console.log("─".repeat(50));

  const child = spawn("node", [filepath], { stdio: "inherit" });
  child.on("exit", (code) => {
    console.log(`\n─────────────────────────────────────────────────`);
    console.log(`Process selesai (exit code: ${code})`);
  });
  return true;
}

// ── Main ──────────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);

// Mode langsung: node run.js b server
if (args.length >= 2) {
  const key = args[0].toLowerCase();
  const role = args[1].toLowerCase();
  if (!VERSIONS[key]) {
    console.log(`❌ Versi tidak dikenal: "${key}". Gunakan: a / b / c / d`);
    process.exit(1);
  }
  showDetail(key);
  runFile(key, role);
  return;
}

// Mode interaktif
showMenu();

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

rl.question("Pilihan kamu: ", (input) => {
  const parts = input.trim().toLowerCase().split(/\s+/);
  const key  = parts[0];
  const role = parts[1];

  if (!VERSIONS[key]) {
    console.log(`\n❌ Pilihan tidak valid. Ketik a, b, c, atau d.`);
    rl.close();
    process.exit(0);
  }

  showDetail(key);

  if (role) {
    rl.close();
    runFile(key, role);
  } else {
    // Versi b punya pilihan server tambahan (malicious)
    if (key === "b") {
      rl.question("\nJalankan sebagai [server/malicious/client]: ", (r) => {
        rl.close();
        runFile(key, r.trim().toLowerCase());
      });
    } else {
      rl.question("\nJalankan sebagai [server/client]: ", (r) => {
        rl.close();
        runFile(key, r.trim().toLowerCase());
      });
    }
  }
});
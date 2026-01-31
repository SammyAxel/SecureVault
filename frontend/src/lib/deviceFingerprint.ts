// Device fingerprinting for trusted device feature
import { UAParser } from 'ua-parser-js';

export interface DeviceInfo {
  fingerprint: string;
  deviceName: string;
  browser: string;
  os: string;
}

// Generate a semi-unique device fingerprint
export async function generateDeviceFingerprint(): Promise<string> {
  const components: string[] = [];
  
  // User agent
  components.push(navigator.userAgent);
  
  // Screen resolution
  components.push(`${screen.width}x${screen.height}x${screen.colorDepth}`);
  
  // Timezone
  components.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
  
  // Language
  components.push(navigator.language);
  
  // Platform
  components.push(navigator.platform);
  
  // Hardware concurrency (CPU cores)
  components.push(String(navigator.hardwareConcurrency || 0));
  
  // Device memory (if available)
  components.push(String((navigator as any).deviceMemory || 0));
  
  // Canvas fingerprint (simple version)
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('SecureVault', 2, 15);
      components.push(canvas.toDataURL());
    }
  } catch (e) {
    // Ignore canvas errors
  }
  
  // Combine all components
  const data = components.join('|');
  
  // Create hash using SubtleCrypto
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return hashHex;
}

// Get device information for display
export function getDeviceInfo(): Omit<DeviceInfo, 'fingerprint'> {
  const parser = new UAParser();
  const result = parser.getResult();
  
  const browser = result.browser.name || 'Unknown Browser';
  const os = result.os.name || 'Unknown OS';
  const deviceType = result.device.type || 'desktop';
  
  // Create a friendly device name
  const deviceName = `${browser} on ${os}`;
  
  return {
    deviceName,
    browser,
    os,
  };
}

// Get full device info including fingerprint
export async function getFullDeviceInfo(): Promise<DeviceInfo> {
  const fingerprint = await generateDeviceFingerprint();
  const info = getDeviceInfo();
  
  return {
    fingerprint,
    ...info,
  };
}

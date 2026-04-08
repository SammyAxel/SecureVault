import { describe, it, expect } from 'vitest';
import { safeContentDisposition } from './sanitize.js';

describe('safeContentDisposition', () => {
  it('handles plain ASCII filenames', () => {
    const result = safeContentDisposition('report.pdf');
    expect(result).toContain('filename="report.pdf"');
    expect(result).toContain("filename*=UTF-8''report.pdf");
  });

  it('escapes double quotes in the ASCII fallback', () => {
    const result = safeContentDisposition('file"name.txt');
    expect(result).not.toContain('filename="file"name.txt"');
    expect(result).toContain('filename="file_name.txt"');
  });

  it('encodes non-ASCII characters in filename*', () => {
    const result = safeContentDisposition('日本語.txt');
    expect(result).toContain('filename*=UTF-8\'\'');
    expect(result).toContain('%E6%97%A5');
  });

  it('replaces non-ASCII in ASCII fallback with underscores', () => {
    const result = safeContentDisposition('café.pdf');
    expect(result).toContain('filename="caf_.pdf"');
  });
});

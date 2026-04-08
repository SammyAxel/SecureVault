import { describe, it, expect } from 'vitest';
import {
  driveSectionFromPath,
  pathForDriveSection,
  isProtectedVaultPath,
  isDriveShellPath,
  isVaultSearchRoute,
  parseSearchQuery,
  pathWithSearch,
  ROUTES,
} from './routes';

describe('driveSectionFromPath', () => {
  it('maps "/" to "home"', () => {
    expect(driveSectionFromPath('/')).toBe('home');
  });
  it('maps "/home" to "home"', () => {
    expect(driveSectionFromPath('/home')).toBe('home');
  });
  it('maps "/drive" to "drive"', () => {
    expect(driveSectionFromPath('/drive')).toBe('drive');
  });
  it('maps "/f/abc" to "drive"', () => {
    expect(driveSectionFromPath('/f/abc')).toBe('drive');
  });
  it('maps "/shared" to "shared"', () => {
    expect(driveSectionFromPath('/shared')).toBe('shared');
  });
  it('maps "/trash" to "trash"', () => {
    expect(driveSectionFromPath('/trash')).toBe('trash');
  });
  it('defaults unknown paths to "home"', () => {
    expect(driveSectionFromPath('/unknown')).toBe('home');
  });
});

describe('pathForDriveSection', () => {
  it('maps "home" to "/home"', () => {
    expect(pathForDriveSection('home')).toBe('/home');
  });
  it('maps "drive" to "/drive"', () => {
    expect(pathForDriveSection('drive')).toBe('/drive');
  });
});

describe('isProtectedVaultPath', () => {
  it('returns false for login/register', () => {
    expect(isProtectedVaultPath('/login')).toBe(false);
    expect(isProtectedVaultPath('/register')).toBe(false);
  });
  it('returns true for drive paths', () => {
    expect(isProtectedVaultPath('/drive')).toBe(true);
    expect(isProtectedVaultPath('/home')).toBe(true);
    expect(isProtectedVaultPath('/admin')).toBe(true);
    expect(isProtectedVaultPath('/profile')).toBe(true);
  });
  it('returns false for unknown paths', () => {
    expect(isProtectedVaultPath('/some-random')).toBe(false);
  });
});

describe('isDriveShellPath', () => {
  it('returns true for vault UI paths', () => {
    expect(isDriveShellPath('/home')).toBe(true);
    expect(isDriveShellPath('/drive')).toBe(true);
    expect(isDriveShellPath('/f/abc')).toBe(true);
  });
  it('returns false for admin/profile/share', () => {
    expect(isDriveShellPath('/admin')).toBe(false);
    expect(isDriveShellPath('/profile')).toBe(false);
    expect(isDriveShellPath('/share/abc')).toBe(false);
  });
});

describe('isVaultSearchRoute', () => {
  it('recognizes search routes', () => {
    expect(isVaultSearchRoute(ROUTES.homeSearch)).toBe(true);
    expect(isVaultSearchRoute(ROUTES.driveSearch)).toBe(true);
  });
  it('rejects non-search routes', () => {
    expect(isVaultSearchRoute(ROUTES.home)).toBe(false);
  });
});

describe('parseSearchQuery', () => {
  it('extracts q param', () => {
    expect(parseSearchQuery('?q=hello')).toBe('hello');
  });
  it('returns empty string for missing q', () => {
    expect(parseSearchQuery('')).toBe('');
    expect(parseSearchQuery('?foo=bar')).toBe('');
  });
});

describe('pathWithSearch', () => {
  it('appends q param', () => {
    expect(pathWithSearch('/drive', 'test')).toBe('/drive?q=test');
  });
  it('returns plain path for empty query', () => {
    expect(pathWithSearch('/drive', '')).toBe('/drive');
    expect(pathWithSearch('/drive', '   ')).toBe('/drive');
  });
});

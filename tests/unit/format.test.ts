import { describe, expect, test } from 'vitest';
import { isoDate, monthDay } from '../../src/lib/format';

describe('date formatting (UTC)', () => {
  const date = new Date('2026-03-07T23:30:00Z');

  test('isoDate gives YYYY-MM-DD', () => {
    expect(isoDate(date)).toBe('2026-03-07');
  });

  test('monthDay gives MM-DD', () => {
    expect(monthDay(date)).toBe('03-07');
  });
});

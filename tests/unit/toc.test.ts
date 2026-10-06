import { describe, expect, test } from 'vitest';
import { tocHeadings } from '../../src/lib/toc';

const h = (depth: number, text: string) => ({ depth, text, slug: text.toLowerCase() });

describe('tocHeadings', () => {
  test('keeps h2 and h3 only', () => {
    const headings = [h(1, 'T'), h(2, 'A'), h(3, 'B'), h(4, 'C'), h(2, 'D')];
    expect(tocHeadings(headings).map((x) => x.text)).toEqual(['A', 'B', 'D']);
  });

  test('is empty when there are fewer than two entries', () => {
    expect(tocHeadings([h(2, 'Only')])).toEqual([]);
    expect(tocHeadings([])).toEqual([]);
  });
});

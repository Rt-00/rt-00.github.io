interface Heading {
  depth: number;
  slug: string;
  text: string;
}

/** h2/h3 entries for the table of contents; empty when a TOC would not help. */
export function tocHeadings<T extends Heading>(headings: T[]): T[] {
  const entries = headings.filter(({ depth }) => depth === 2 || depth === 3);
  return entries.length >= 2 ? entries : [];
}

const WORDS_PER_MINUTE = 220;

/** Strips markdown/MDX syntax that is not read as prose. */
function proseOf(markdown: string): string {
  return markdown
    .replace(/^(```|~~~)[\s\S]*?^\1/gm, ' ') // fenced code blocks
    .replace(/^(import|export)\s.*$/gm, ' ') // mdx imports/exports
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ') // images
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1') // links -> text
    .replace(/<[^>]+>/g, ' ') // html tags
    .replace(/^\s*([-+*]|\d+\.)\s+/gm, ' ') // list markers
    .replace(/^-{3,}$/gm, ' ') // thematic breaks
    .replace(/[#*_`>~|]+/g, ' '); // inline markers
}

export function readingStats(markdown: string): { words: number; minutes: number } {
  const words = proseOf(markdown).split(/\s+/).filter(Boolean).length;
  return { words, minutes: Math.max(1, Math.ceil(words / WORDS_PER_MINUTE)) };
}

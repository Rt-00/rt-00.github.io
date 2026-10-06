/** YYYY-MM-DD in UTC, so dates from frontmatter never shift with the build timezone. */
export function isoDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** MM-DD in UTC. */
export function monthDay(date: Date): string {
  return isoDate(date).slice(5);
}

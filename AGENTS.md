# rt-00.github.io — terminal-style blog

Personal blog. Terminal aesthetic (visual only, not interactive), strictly black/white + grays,
content-first. Posts in Markdown/MDX. Deployed to GitHub Pages at https://rt-00.github.io.

## Stack

- Astro 7 (static output), TypeScript strict, pnpm 12 (via corepack).
- TypeScript is pinned to 6.x because `astro check` does not support TS 7 yet.
- Markdown is rendered by Astro 7's default `satteri` processor — avoid remark/rehype plugins;
  derive data (reading time, etc.) from `entry.body` in `src/lib/` instead.

## Commands

| Command             | What                                            |
| ------------------- | ----------------------------------------------- |
| `pnpm dev`          | dev server (`astro dev --background` ok)        |
| `pnpm build`        | `astro build` + Pagefind index into `dist`      |
| `pnpm preview`      | serve `dist`                                    |
| `pnpm test`         | Vitest unit tests (`tests/unit`)                |
| `pnpm test:e2e`     | Playwright against `pnpm preview` (build first) |
| `pnpm check`        | astro check (types)                             |
| `pnpm lint`         | ESLint                                          |
| `pnpm format:check` | Prettier                                        |

## Conventions

- `pnpm preview` auto-backgrounds when an agent is detected; Playwright uses `--ignore-lock` to keep it in the foreground.
- TDD: write the failing test first (unit for `src/lib/*`, e2e for pages).
- Conventional Commits, small and semantic. One branch per feature (`feat/<scope>`), PR, rebase-merge.
- UI copy is English. Each post declares `lang: pt | en` (shown as `[pt]`/`[en]`).
- Keep this file updated as the source of truth for future agents.

## Layout

- `src/site.ts` — site metadata, prompt, nav.
- `src/content/posts/` — posts (`<slug>.md(x)` or `<slug>/index.md` + images). Schema in `src/content.config.ts`.
- `src/lib/` — pure helpers (unit-tested, no Astro imports) + `content.ts` (Astro wrapper: `getPosts()`).
- `src/layouts/Base.astro` — header/nav/theme toggle/footer prompt with blinking cursor.
- `src/components/Command.astro` — renders `rt@blog:~$ <cmd>` at the top of each page.
- `src/shiki/mono.ts` — grayscale Shiki themes (light/dark via CSS vars, `defaultColor: false`).

## Decisions

- Font: JetBrains Mono via `@fontsource/jetbrains-mono` (self-hosted).
- Theme: follows `prefers-color-scheme`, toggle persisted in `localStorage` (`theme`).
- Prompt identity: `rt@blog:~$`.
- Home lists posts `ls -l` style grouped by year.

## Status

- [x] Scaffold + tooling
- [x] CI (format, lint, check, unit, build, e2e)
- [x] Content collection, layout + theme, home `ls -l`

import type { ThemeRegistration } from 'shiki';

/** Grayscale syntax theme: structure through weight/style and shades, never hue. */
function mono(type: 'light' | 'dark'): ThemeRegistration {
  const [fg, bg, muted, soft] =
    type === 'dark'
      ? ['#ededed', '#0d0d0d', '#7a7a7a', '#b5b5b5']
      : ['#111111', '#f4f4f4', '#7a7a7a', '#444444'];
  return {
    name: `mono-${type}`,
    type,
    colors: { 'editor.foreground': fg, 'editor.background': bg },
    tokenColors: [
      { settings: { foreground: fg } },
      {
        scope: ['comment', 'punctuation.definition.comment'],
        settings: { foreground: muted, fontStyle: 'italic' },
      },
      {
        scope: ['keyword', 'storage', 'keyword.control', 'keyword.operator.new'],
        settings: { fontStyle: 'bold' },
      },
      {
        scope: ['string', 'markup.inline.raw', 'constant.other.symbol'],
        settings: { foreground: soft },
      },
      {
        scope: ['constant.numeric', 'constant.language'],
        settings: { foreground: soft, fontStyle: 'bold' },
      },
      { scope: ['entity.name.function', 'support.function'], settings: { fontStyle: 'underline' } },
      { scope: ['punctuation', 'meta.brace'], settings: { foreground: muted } },
      { scope: ['markup.heading'], settings: { fontStyle: 'bold' } },
      { scope: ['markup.deleted'], settings: { foreground: muted, fontStyle: 'strikethrough' } },
      { scope: ['markup.inserted'], settings: { fontStyle: 'bold' } },
    ],
  };
}

export const monoLight = mono('light');
export const monoDark = mono('dark');

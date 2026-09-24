/**
 * mask-profanity — copied verbatim from southern-wine-country's
 * `src/lib/mask-profanity.mjs` @ 572ff7e (build plan §5.1: "Copy | same").
 * Cursing is ALLOWED when writing a post; this cleans the PUBLISHED output,
 * masking swears to the first letter + asterisks (F***, S***).
 *
 * **Stage-1 status.** Blog/learn content is out of scope for P2 stage 1
 * (see this repo's stage-1 scope note: "Out of scope for stage 1: ...
 * blog and learn content"), so nothing wires `remarkMaskProfanity` into
 * `astro.config.mjs`'s `markdown.remarkPlugins` yet — there is no content
 * collection for it to run over. Copied now (rather than deferred) so the
 * ONE mask function exists ready for the blog/learn port, instead of a
 * second copy drifting in later.
 */
const GREEDY = [
  'fuck', 'shit', 'bitch', 'cunt', 'motherfuck', 'bullshit', 'asshole',
  'dumbass', 'jackass', 'goddamn', 'dickhead', 'bastard', 'wank', 'twat',
  'bollock', 'douche', 'slut', 'shithead',
];
const EXACT = ['ass', 'damn', 'piss', 'dick', 'cock', 'crap', 'prick', 'whore'];

const greedyRe = new RegExp('\\b(' + GREEDY.join('|') + ')\\w*', 'gi');
const exactRe = new RegExp('\\b(' + EXACT.join('|') + ')\\b', 'gi');

const maskWord = (w) => w[0] + '*'.repeat(Math.max(1, w.length - 1));

export function maskProfanity(text) {
  if (typeof text !== 'string' || !text) return text;
  return text.replace(greedyRe, maskWord).replace(exactRe, maskWord);
}

/** remark plugin: mask text nodes in blog-post Markdown bodies (code left
 * intact). Scoped to `content/blog` once that collection exists. */
export default function remarkMaskProfanity() {
  return (tree, file) => {
    const p = (file && (file.path || (file.history && file.history[0]))) || '';
    if (!/[\\/]content[\\/]blog[\\/]/.test(p)) return;
    const walk = (node) => {
      if (node.type === 'code' || node.type === 'inlineCode') return;
      if (node.type === 'text' && typeof node.value === 'string') {
        node.value = maskProfanity(node.value);
      }
      if (Array.isArray(node.children)) node.children.forEach(walk);
    };
    walk(tree);
  };
}

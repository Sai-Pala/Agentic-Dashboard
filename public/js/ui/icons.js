/**
 * The icon set
 * ============
 *
 * Hand-drawn monoline SVG paths, no icon font and no emoji anywhere in the UI — consistent
 * with this app's no-external-dependency aesthetic.
 *
 * Moved verbatim out of the single inline <script> during the Phase 4 split.
 */

export const ICONS = {
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.8-4.8"/>',
  wrench: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.7 2.7-2-2 2.7-2.7Z"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M3 12h3M18 12h3M4.9 19.1l2.1-2.1M17 7l2.1-2.1"/>',
  hourglass: '<path d="M6.5 3h11M6.5 21h11M7.5 3c0 5 4.5 6 4.5 9s-4.5 4-4.5 9M16.5 3c0 5-4.5 6-4.5 9s4.5 4 4.5 9"/>',
  inbox: '<path d="M3.5 12h4.3l1.8 3h4.8l1.8-3h4.3"/><path d="M3.5 12 5 5h14l1.5 7v6a1 1 0 0 1-1 1H4.5a1 1 0 0 1-1-1v-6Z"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
  checkCircle: '<circle cx="12" cy="12" r="8.5"/><path d="m8 12.3 2.6 2.6 5.2-5.2"/>',
  folder: '<path d="M3 6.5a1.5 1.5 0 0 1 1.5-1.5h4l2 2h8.5a1.5 1.5 0 0 1 1.5 1.5v9a1.5 1.5 0 0 1-1.5 1.5h-14A1.5 1.5 0 0 1 3 17.5v-11Z"/>',
  trending: '<path d="m3 16 6-6 4 4 8-8"/><path d="M15 6h6v6"/>',
  radar: '<circle cx="12" cy="12" r="9"/><path d="M12 12 18 8"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21"/>',
  package: '<path d="M3.5 8.2 12 4l8.5 4.2v7.6L12 20 3.5 15.8V8.2Z"/><path d="M3.5 8.2 12 12l8.5-3.8"/><path d="M12 12v8"/>',
  edit: '<path d="M4 20h4l10-10a2 2 0 0 0 0-2.8L16.8 5a2 2 0 0 0-2.8 0L4 15v5Z"/><path d="m13.5 6.5 4 4"/>',
  branch: '<circle cx="6" cy="4.5" r="2.2"/><circle cx="6" cy="19.5" r="2.2"/><circle cx="18" cy="7.5" r="2.2"/><path d="M6 6.7V17.3"/><path d="M18 9.7A7 7 0 0 1 11 16.5"/>',
  terminal: '<rect x="3" y="4.5" width="18" height="15" rx="1.8"/><path d="m7.5 9.5 3 2.7-3 2.7"/><path d="M13 15.2h4"/>',
  more: '<circle cx="12" cy="5.5" r="1.7" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.7" fill="currentColor" stroke="none"/><circle cx="12" cy="18.5" r="1.7" fill="currentColor" stroke="none"/>',
  arrowRight: '<path d="M4 12h16"/><path d="m13 5 7 7-7 7"/>',
  fastForward: '<path d="m5 5 7 7-7 7"/><path d="m13 5 7 7-7 7"/>',
  // Distinct from each other on purpose (Remediation Loop's advance vs. run-all buttons sit
  // right next to each other at small size — a single chevron vs. a skip-to-end glyph reads
  // clearly apart, where two chevron variants (arrowRight/fastForward above) didn't).
  chevronRight: '<path d="m9 5 7 7-7 7"/>',
  skipForward: '<path d="M6 5v14l10-7L6 5Z"/><path d="M19 5v14"/>',
};

export function icon(name, cls) {
  return `<svg class="icon${cls ? ' ' + cls : ''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ''}</svg>`;
}

/**
 * Wires view ids to the code that renders them.
 *
 * This is the only module that imports both the nav and the views, which is what keeps the
 * dependency one-directional: views import `nav.js` to navigate, and nothing imports back into
 * them except this file. Add a screen by adding a line here — `nav.js` needs no change.
 */

import { registerView, registerBadgeHook } from './nav.js';
import { renderDashboard } from './views/dashboard.js';
import { renderFindingsView } from './views/findings/index.js';
import { openSurfaceView } from './views/surface.js';
import { renderSettings } from './views/settings.js';
import { updateTimelineClockDots } from './views/timeline.js';

/**
 * Views not listed here are static markup — `showView` just unhides them.
 * Called once from main.js, before initNav().
 */
export function registerViews() {
  registerView('dashboard', renderDashboard);
  registerView('findings', renderFindingsView);
  registerView('surface', openSurfaceView);
  registerView('settings', renderSettings);

  registerBadgeHook(updateTimelineClockDots);
}

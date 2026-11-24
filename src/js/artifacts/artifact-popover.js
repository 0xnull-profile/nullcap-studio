'use strict';
/* A18 - only the Bottino information popover hover lifetime changes.
 * A16 already closes on outside pointerdown, repeated click and Escape.
 * Click-open popovers must persist independently of hover state.
 */
function nc18WireInfoPopover() {
  const button = document.getElementById('nc16InformationToggle');
  const popover = document.getElementById('nc16InfoPopover');
  if (!button || !popover) return;
  let leaveTimer = null;
  const cancelHoverClose = () => {
    if (leaveTimer !== null) {
      clearTimeout(leaveTimer);
      leaveTimer = null;
    }
  };
  const scheduleHoverClose = () => {
    cancelHoverClose();
    if (nc16UI.infoOrigin !== 'hover' || !nc16UI.infoOpen) return;
    /* The popover is positioned 6px away from the button; allow the cursor
       to cross this gap before deciding it has left the whole hover region. */
    leaveTimer = setTimeout(() => {
      leaveTimer = null;
      if (nc16UI.infoOpen && nc16UI.infoOrigin === 'hover' &&
          !button.matches(':hover') && !popover.matches(':hover')) nc16InfoClose();
    }, 100);
  };
  button.addEventListener('pointerenter', cancelHoverClose);
  button.addEventListener('pointerleave', scheduleHoverClose);
  popover.addEventListener('pointerenter', cancelHoverClose);
  popover.addEventListener('pointerleave', scheduleHoverClose);
  document.addEventListener('pointerdown', cancelHoverClose);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') cancelHoverClose();
  });
}
const nc18PriorWire = wireUI;
wireUI = function () {
  nc18PriorWire();
  nc18WireInfoPopover();
};

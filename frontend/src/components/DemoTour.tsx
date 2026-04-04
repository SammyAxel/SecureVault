import { createSignal, createEffect, onCleanup, Show, For } from 'solid-js';

export interface TourStep {
  /** CSS selector for the target element (e.g. '[data-demo-tour="upload"]') */
  selector: string;
  /** Speech-bubble title */
  title: string;
  /** Speech-bubble body text */
  body: string;
  /** Which side to place the popover relative to the target */
  placement?: 'top' | 'bottom' | 'left' | 'right';
}

const TOUR_DONE_KEY = 'securevault_demo_tour_done';

const STEPS: TourStep[] = [
  {
    selector: '[data-demo-tour="logo"]',
    title: 'Welcome to SecureVault',
    body: 'This is the main logo. Click it anytime to go back to the Home page.',
    placement: 'bottom',
  },
  {
    selector: '[data-demo-tour="sidebar-drive"]',
    title: 'My Drive',
    body: 'All your encrypted files and folders live here. Try uploading a file!',
    placement: 'right',
  },
  {
    selector: '[data-demo-tour="sidebar-shared"]',
    title: 'Shared with Me',
    body: 'Files that others have shared with you appear here.',
    placement: 'right',
  },
  {
    selector: '[data-demo-tour="sidebar-trash"]',
    title: 'Trash',
    body: 'Deleted files go to Trash. You can restore or permanently delete them.',
    placement: 'right',
  },
  {
    selector: '[data-demo-tour="admin-btn"]',
    title: 'Admin Dashboard',
    body: 'As the demo admin, you can manage users, view audit logs, and configure settings here.',
    placement: 'bottom',
  },
  {
    selector: '[data-demo-tour="profile-btn"]',
    title: 'Profile & Logout',
    body: 'View your profile or log out. In demo mode, logging out deletes all your uploaded files.',
    placement: 'bottom',
  },
];

export default function DemoTour(props: { active: boolean; onClose: () => void }) {
  const [step, setStep] = createSignal(0);
  const [rect, setRect] = createSignal<DOMRect | null>(null);

  const currentStep = () => STEPS[step()];

  function measureTarget() {
    const s = currentStep();
    if (!s) return;
    const el = document.querySelector(s.selector);
    if (el) {
      setRect(el.getBoundingClientRect());
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } else {
      setRect(null);
    }
  }

  createEffect(() => {
    if (!props.active) return;
    step();
    measureTarget();
    const onResize = () => measureTarget();
    window.addEventListener('resize', onResize);
    window.addEventListener('scroll', onResize, true);
    onCleanup(() => {
      window.removeEventListener('resize', onResize);
      window.removeEventListener('scroll', onResize, true);
    });
  });

  function next() {
    if (step() < STEPS.length - 1) {
      setStep((s) => s + 1);
    } else {
      finish();
    }
  }
  function prev() {
    if (step() > 0) setStep((s) => s - 1);
  }
  function finish() {
    try { localStorage.setItem(TOUR_DONE_KEY, '1'); } catch { /* noop */ }
    props.onClose();
  }

  const popoverStyle = () => {
    const r = rect();
    if (!r) return { top: '50%', left: '50%', transform: 'translate(-50%, -50%)' };
    const placement = currentStep()?.placement ?? 'bottom';
    const gap = 12;
    const style: Record<string, string> = { position: 'fixed' };
    switch (placement) {
      case 'bottom':
        style.top = `${r.bottom + gap}px`;
        style.left = `${r.left + r.width / 2}px`;
        style.transform = 'translateX(-50%)';
        break;
      case 'top':
        style.bottom = `${window.innerHeight - r.top + gap}px`;
        style.left = `${r.left + r.width / 2}px`;
        style.transform = 'translateX(-50%)';
        break;
      case 'right':
        style.top = `${r.top + r.height / 2}px`;
        style.left = `${r.right + gap}px`;
        style.transform = 'translateY(-50%)';
        break;
      case 'left':
        style.top = `${r.top + r.height / 2}px`;
        style.right = `${window.innerWidth - r.left + gap}px`;
        style.transform = 'translateY(-50%)';
        break;
    }
    return style;
  };

  return (
    <Show when={props.active}>
      {/* Backdrop with cut-out */}
      <div class="fixed inset-0 z-[200]" onClick={(e) => { if (e.target === e.currentTarget) finish(); }}>
        {/* Dark overlay */}
        <svg class="absolute inset-0 w-full h-full" style={{ 'pointer-events': 'none' }}>
          <defs>
            <mask id="tour-mask">
              <rect width="100%" height="100%" fill="white" />
              <Show when={rect()}>
                {(() => {
                  const r = rect()!;
                  const pad = 6;
                  return (
                    <rect
                      x={r.left - pad}
                      y={r.top - pad}
                      width={r.width + pad * 2}
                      height={r.height + pad * 2}
                      rx="8"
                      fill="black"
                    />
                  );
                })()}
              </Show>
            </mask>
          </defs>
          <rect width="100%" height="100%" fill="rgba(0,0,0,0.6)" mask="url(#tour-mask)" />
        </svg>

        {/* Highlight border */}
        <Show when={rect()}>
          {(() => {
            const r = rect()!;
            const pad = 6;
            return (
              <div
                class="absolute rounded-lg ring-2 ring-primary-400 ring-offset-2 ring-offset-transparent pointer-events-none"
                style={{
                  top: `${r.top - pad}px`,
                  left: `${r.left - pad}px`,
                  width: `${r.width + pad * 2}px`,
                  height: `${r.height + pad * 2}px`,
                }}
              />
            );
          })()}
        </Show>

        {/* Speech bubble */}
        <div
          class="absolute z-[210] w-72 sm:w-80 bg-gray-800 border border-gray-600 rounded-xl shadow-xl p-4"
          style={popoverStyle()}
        >
          {/* Arrow indicator */}
          <Show when={rect()}>
            {(() => {
              const placement = currentStep()?.placement ?? 'bottom';
              const arrowClasses: Record<string, string> = {
                bottom: '-top-2 left-1/2 -translate-x-1/2 border-l-transparent border-r-transparent border-t-transparent border-b-gray-600',
                top: '-bottom-2 left-1/2 -translate-x-1/2 border-l-transparent border-r-transparent border-b-transparent border-t-gray-600',
                right: '-left-2 top-1/2 -translate-y-1/2 border-t-transparent border-b-transparent border-l-transparent border-r-gray-600',
                left: '-right-2 top-1/2 -translate-y-1/2 border-t-transparent border-b-transparent border-r-transparent border-l-gray-600',
              };
              return (
                <div
                  class={`absolute w-0 h-0 border-[8px] ${arrowClasses[placement]}`}
                />
              );
            })()}
          </Show>

          <h3 class="text-white font-semibold text-sm mb-1">{currentStep()?.title}</h3>
          <p class="text-gray-300 text-sm leading-relaxed mb-4">{currentStep()?.body}</p>

          {/* Step indicator dots */}
          <div class="flex items-center justify-center gap-1.5 mb-3">
            <For each={STEPS}>
              {(_, i) => (
                <div
                  class={`w-1.5 h-1.5 rounded-full transition-colors ${
                    i() === step() ? 'bg-primary-400' : 'bg-gray-600'
                  }`}
                />
              )}
            </For>
          </div>

          <div class="flex items-center justify-between">
            <button
              type="button"
              onClick={finish}
              class="text-xs text-gray-400 hover:text-white"
            >
              Skip
            </button>
            <div class="flex gap-2">
              <Show when={step() > 0}>
                <button
                  type="button"
                  onClick={prev}
                  class="px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-white text-xs"
                >
                  Back
                </button>
              </Show>
              <button
                type="button"
                onClick={next}
                class="px-3 py-1.5 rounded-lg bg-primary-600 hover:bg-primary-700 text-white text-xs font-medium"
              >
                {step() === STEPS.length - 1 ? 'Finish' : 'Next'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </Show>
  );
}

export function shouldAutoStartTour(): boolean {
  try {
    return !localStorage.getItem(TOUR_DONE_KEY);
  } catch {
    return false;
  }
}

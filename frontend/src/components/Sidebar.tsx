import DriveNavPanel from './DriveNavPanel';
import type { DriveSection } from '../lib/routes';

export type { DriveSection };

export default function Sidebar(props: {
  active: DriveSection;
  onNavigate: (section: DriveSection) => void;
}) {
  return (
    <aside class="hidden lg:flex lg:flex-col w-64 shrink-0" aria-label="Drive sidebar">
      <div class="sticky top-0 pt-6">
        <DriveNavPanel active={props.active} onNavigate={props.onNavigate} />
      </div>
    </aside>
  );
}

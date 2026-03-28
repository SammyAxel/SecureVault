import { onMount, onCleanup } from 'solid-js';
import Cropper from 'cropperjs';
import 'cropperjs/dist/cropper.css';

interface AvatarCropperProps {
  imageSrc: string;
  onSave: (croppedDataUrl: string) => void;
  onCancel: () => void;
}

const CROP_SIZE = 400; // Output size for avatar (square, displayed as circle)
const MAX_OUTPUT_KB = 450; // Stay under 500KB limit with some margin

export function AvatarCropper(props: AvatarCropperProps) {
  let containerRef: HTMLDivElement | undefined;
  let imgRef: HTMLImageElement | undefined;
  let cropper: Cropper | null = null;

  onMount(() => {
    if (!imgRef || !containerRef) return;

    cropper = new Cropper(imgRef, {
      aspectRatio: 1, // Square crop for circular avatar display
      viewMode: 1, // Restrict crop box to not exceed the size of the canvas
      dragMode: 'move',
      autoCropArea: 0.8,
      restore: false,
      guides: true,
      center: true,
      highlight: false,
      cropBoxMovable: true,
      cropBoxResizable: true,
      toggleDragModeOnDblclick: false,
    });
  });

  onCleanup(() => {
    cropper?.destroy();
    cropper = null;
  });

  const handleSave = () => {
    if (!cropper) return;

    const canvas = cropper.getCroppedCanvas({
      width: CROP_SIZE,
      height: CROP_SIZE,
      imageSmoothingEnabled: true,
      imageSmoothingQuality: 'high',
    });

    if (!canvas) return;

    // Compress to fit within size limit
    let quality = 0.92;
    let dataUrl = canvas.toDataURL('image/jpeg', quality);

    while (dataUrl.length > MAX_OUTPUT_KB * 1024 && quality > 0.1) {
      quality -= 0.1;
      dataUrl = canvas.toDataURL('image/jpeg', quality);
    }

    // If still too large, try PNG (sometimes smaller for simple images)
    if (dataUrl.length > MAX_OUTPUT_KB * 1024) {
      dataUrl = canvas.toDataURL('image/png');
    }

    props.onSave(dataUrl);
  };

  return (
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 sv-modal-overlay">
      <div class="bg-gray-800 rounded-xl max-w-2xl w-full overflow-hidden shadow-xl sv-modal-panel">
        <div class="p-4 border-b border-gray-700">
          <h3 class="text-lg font-semibold text-white">Adjust your profile picture</h3>
          <p class="text-gray-400 text-sm mt-1">
            Drag to position and pinch/scroll to zoom. Adjust the circle to frame your photo.
          </p>
        </div>

        <div class="relative bg-gray-900 avatar-cropper-area" style={{ height: 'min(70vh, 400px)' }}>
          <div ref={containerRef} class="h-full w-full overflow-hidden">
            <img
              ref={imgRef}
              src={props.imageSrc}
              alt="Crop preview"
              class="block max-w-full max-h-full"
              style={{ display: 'block' }}
            />
          </div>
        </div>

        <div class="p-4 flex gap-3 justify-end border-t border-gray-700">
          <button
            onClick={props.onCancel}
            class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            class="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

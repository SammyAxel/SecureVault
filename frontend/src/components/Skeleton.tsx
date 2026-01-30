export function SkeletonText(props: { width?: string; height?: string }) {
  return (
    <div 
      class={`animate-pulse bg-gray-700 rounded ${props.height || 'h-4'} ${props.width || 'w-full'}`}
    />
  );
}

export function SkeletonFileRow() {
  return (
    <div class="grid grid-cols-[auto_1fr_auto_auto_auto] gap-4 items-center px-4 py-3 hover:bg-gray-800 rounded">
      {/* Icon skeleton */}
      <div class="w-6 h-6 animate-pulse bg-gray-700 rounded" />
      
      {/* Filename skeleton */}
      <div class="space-y-1">
        <div class="h-4 w-48 animate-pulse bg-gray-700 rounded" />
      </div>
      
      {/* Size skeleton */}
      <div class="h-4 w-16 animate-pulse bg-gray-700 rounded" />
      
      {/* Date skeleton */}
      <div class="h-4 w-24 animate-pulse bg-gray-700 rounded" />
      
      {/* Actions skeleton */}
      <div class="flex gap-2">
        <div class="w-8 h-8 animate-pulse bg-gray-700 rounded" />
        <div class="w-8 h-8 animate-pulse bg-gray-700 rounded" />
        <div class="w-8 h-8 animate-pulse bg-gray-700 rounded" />
      </div>
    </div>
  );
}

export function SkeletonDashboard() {
  return (
    <div class="p-6 space-y-4">
      {/* Header skeleton */}
      <div class="flex justify-between items-center mb-6">
        <div class="h-8 w-48 animate-pulse bg-gray-700 rounded" />
        <div class="flex gap-2">
          <div class="w-32 h-10 animate-pulse bg-gray-700 rounded" />
          <div class="w-32 h-10 animate-pulse bg-gray-700 rounded" />
        </div>
      </div>

      {/* Search & filter skeleton */}
      <div class="flex gap-4 mb-4">
        <div class="flex-1 h-10 animate-pulse bg-gray-700 rounded" />
        <div class="w-40 h-10 animate-pulse bg-gray-700 rounded" />
        <div class="w-32 h-10 animate-pulse bg-gray-700 rounded" />
      </div>

      {/* File list skeleton */}
      <div class="bg-gray-900 rounded-lg border border-gray-800">
        <div class="grid grid-cols-[auto_1fr_auto_auto_auto] gap-4 px-4 py-3 bg-gray-800 rounded-t-lg border-b border-gray-700">
          <div class="h-4 w-4 animate-pulse bg-gray-600 rounded" />
          <div class="h-4 w-16 animate-pulse bg-gray-600 rounded" />
          <div class="h-4 w-12 animate-pulse bg-gray-600 rounded" />
          <div class="h-4 w-20 animate-pulse bg-gray-600 rounded" />
          <div class="h-4 w-16 animate-pulse bg-gray-600 rounded" />
        </div>
        <div class="divide-y divide-gray-800">
          {Array.from({ length: 8 }).map((_, i) => (
            <SkeletonFileRow key={i} />
          ))}
        </div>
      </div>
    </div>
  );
}

export function SkeletonFileViewer() {
  return (
    <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div class="w-full max-w-6xl bg-gray-800 rounded-lg shadow-2xl p-6 space-y-6">
        {/* Header skeleton */}
        <div class="flex items-center justify-between mb-4">
          <div class="space-y-2">
            <div class="h-8 w-64 animate-pulse bg-gray-700 rounded" />
            <div class="h-4 w-32 animate-pulse bg-gray-700 rounded" />
          </div>
          <div class="w-32 h-10 animate-pulse bg-gray-700 rounded" />
        </div>

        {/* Preview area skeleton */}
        <div class="bg-gray-900 rounded-lg border border-gray-700 p-8">
          <div class="flex flex-col items-center justify-center space-y-4">
            <div class="w-24 h-24 animate-pulse bg-gray-700 rounded-full" />
            <div class="h-4 w-48 animate-pulse bg-gray-700 rounded" />
          </div>
        </div>
      </div>
    </div>
  );
}

export function SkeletonCard() {
  return (
    <div class="bg-gray-800 rounded-lg p-4 space-y-3">
      <div class="h-5 w-32 animate-pulse bg-gray-700 rounded" />
      <div class="h-8 w-24 animate-pulse bg-gray-700 rounded" />
      <div class="h-4 w-full animate-pulse bg-gray-700 rounded" />
    </div>
  );
}

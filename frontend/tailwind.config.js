/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
          950: '#082f49',
        },
        /** Semantic neutrals for cards/modals (prefer these in new UI). */
        vault: {
          canvas: '#0a0a0b',
          panel: '#1f2937',
          'panel-muted': 'rgba(31, 41, 55, 0.6)',
          border: '#374151',
          'border-strong': '#4b5563',
        },
      },
      boxShadow: {
        'vault-float': '0 25px 50px -12px rgba(0, 0, 0, 0.45)',
      },
    },
  },
  plugins: [],
};

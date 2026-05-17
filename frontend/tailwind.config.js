/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        primary: {
          50:  '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
          950: '#1e1b4b',
        },
        /** Semantic neutrals for cards/modals (prefer these in new UI). */
        vault: {
          canvas: '#07070d',
          panel: '#0f0f1a',
          'panel-soft': '#16162a',
          border: '#2a2a40',
          'border-strong': '#3d3d5c',
          'panel-muted': 'rgba(15, 15, 26, 0.6)',
        },
      },
      boxShadow: {
        'vault-float': '0 25px 50px -12px rgba(0, 0, 0, 0.45)',
        'vault-glow': '0 0 0 1px rgba(99, 102, 241, 0.25), 0 4px 24px rgba(99, 102, 241, 0.12)',
      },
    },
  },
  plugins: [],
};

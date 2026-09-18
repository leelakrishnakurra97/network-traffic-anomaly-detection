/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#060a12',
          900: '#0c1322',
          850: '#111a2e',
          800: '#17233d',
          700: '#223254',
          accent: '#06b6d4', // Cyan
          warning: '#f59e0b', // Amber
          danger: '#f43f5e', // Rose
          success: '#10b981' // Emerald
        }
      }
    },
  },
  plugins: [],
}

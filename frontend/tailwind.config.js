/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#030712',
          card: '#0B0F19',
          border: '#1F2937',
          accent: '#00F0FF',
          pink: '#FF007A',
          green: '#00FF66',
          danger: '#FF2A6D',
        }
      },
      boxShadow: {
        'glow-red': '0 0 25px -5px rgba(255, 42, 109, 0.5)',
        'glow-green': '0 0 25px -5px rgba(0, 255, 102, 0.5)',
        'glow-blue': '0 0 25px -5px rgba(0, 240, 255, 0.4)',
      }
    },
  },
  plugins: [],
}

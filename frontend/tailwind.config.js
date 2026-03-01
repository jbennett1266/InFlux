/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        influx: {
          blue: {
            50: '#f0f7ff',
            100: '#e0effe',
            200: '#bae0fd',
            300: '#7cc8fb',
            400: '#38aaf7',
            500: '#0e8ce4',
            600: '#026fc1',
            700: '#03589c',
            800: '#074b81',
            900: '#0c406b',
            950: '#082949',
          }
        }
      }
    },
  },
  plugins: [],
};

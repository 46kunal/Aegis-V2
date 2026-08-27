/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          950: "#04070d",
          900: "#08111f",
          800: "#0f1d33",
          700: "#14263d",
          600: "#1c3554",
          500: "#24598a",
          400: "#3a86c8",
          300: "#59b3f5",
          200: "#89d4ff",
          100: "#d4efff"
        },
        signal: {
          low: "#22c55e",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#ef4444"
        }
      },
      boxShadow: {
        scanner: "0 0 0 1px rgba(89,179,245,0.22), 0 14px 35px rgba(7,13,26,0.55)",
      },
      fontFamily: {
        display: ["Rajdhani", "sans-serif"],
        body: ["Space Grotesk", "sans-serif"],
      },
      backgroundImage: {
        grid: "radial-gradient(circle at 1px 1px, rgba(89,179,245,0.12) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};

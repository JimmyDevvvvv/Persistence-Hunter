/** @type {import("tailwindcss").Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono:    ["JetBrains Mono", "Fira Code", "monospace"],
        display: ["Syne", "sans-serif"],
        body:    ["DM Sans", "sans-serif"],
      },
      colors: {
        bg: {
          base:    "#0a0c0f",
          surface: "#111318",
          raised:  "#181c23",
          border:  "#1f2430",
          hover:   "#232837",
        },
      },
      animation: {
        "fade-in":  "fadeIn 0.2s ease-out",
        "slide-up": "slideUp 0.25s ease-out",
      },
      keyframes: {
        fadeIn:  { "0%": { opacity: 0 }, "100%": { opacity: 1 } },
        slideUp: { "0%": { opacity: 0, transform: "translateY(8px)" }, "100%": { opacity: 1, transform: "translateY(0)" } },
      },
    },
  },
  plugins: [],
}

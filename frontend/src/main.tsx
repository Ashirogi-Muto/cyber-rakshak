import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

console.log("main.tsx loaded");

const rootElement = document.getElementById("root");
if (rootElement) {
  console.log("Root element found, rendering App");
  createRoot(rootElement).render(<App />);
} else {
  console.error("Root element not found!");
}
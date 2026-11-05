"use client";
import { useEffect, useRef } from "react";
declare global { interface Window { Charts?: {line: (el: HTMLElement, options: unknown) => void} } }
let chartScript: Promise<void> | null = null;
export default function TrendChart({values, labels, theme}: {values: number[]; labels: string[]; theme: string}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let dead = false;
    let observer: ResizeObserver | undefined;
    if (!chartScript) chartScript = new Promise((resolve, reject) => {const script = document.createElement("script"); script.src = "/vendor/charts.js"; script.onload = () => resolve(); script.onerror = reject; document.head.appendChild(script);});
    chartScript.then(() => {
      if (dead || !ref.current) return;
      const draw = () => {if (ref.current) window.Charts?.line(ref.current, {labels, series: [{name: "Analyzer findings", values}], height: 164, min: 0, endLabel: true, yTicks: Array.from({length: 5}, (_, i) => i * Math.max(1, Math.ceil(Math.max(...values) / 4)))});};
      draw(); observer = new ResizeObserver(draw); observer.observe(ref.current);
    }).catch(() => {});
    return () => {dead = true; observer?.disconnect();};
  }, [values, labels, theme]);
  return <div className="trend-chart" ref={ref} aria-label={`Analyzer findings across scans: ${values.join(", ")}`}/>;
}

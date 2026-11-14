"use client";

import { useLayoutEffect, useRef, type ButtonHTMLAttributes, type HTMLAttributes, type Ref } from "react";
import { createMotionChannel } from "@/lib/parallel-motion";
import styles from "./parallel-motion.module.css";

type Channel = ReturnType<typeof createMotionChannel>;

/** One measured selection surface, independent of the content and its hit targets. */
export function MotionSelection({ as: Tag = "div", activeKey, layoutKey = "", children, className = "", ...props }: HTMLAttributes<HTMLElement> & {
  as?: "div" | "nav";
  activeKey: string;
  layoutKey?: string;
}) {
  const root = useRef<HTMLElement>(null);
  const surface = useRef<HTMLSpanElement>(null);
  const channel = useRef<Channel | null>(null);
  const refresh = useRef<(immediate?: boolean) => void>(() => {});

  useLayoutEffect(() => {
    const container = root.current;
    const pill = surface.current;
    if (!container || !pill) return;
    let disposed = false;
    let positioned = false;
    let values = [0, 0, 1, 1];
    let size = [1, 1];
    const paint = (next: number[]) => {
      values = next;
      pill.style.transform = `translate3d(${next[0]}px,${next[1]}px,0) scale(${Math.max(.01, next[2] / size[0])},${Math.max(.01, next[3] / size[1])})`;
    };
    const motion = createMotionChannel({
      read: () => values,
      write: paint,
      onRest: () => { pill.style.willChange = "auto"; container.dataset.motionRunning = "false"; },
    });
    channel.current = motion;
    const measure = (immediate = false) => {
      if (disposed) return;
      const selected = container.querySelector<HTMLElement>('[data-motion-item][aria-pressed="true"], [data-motion-item][aria-current]');
      if (!selected) {
        motion.stop(); pill.style.opacity = "0"; positioned = false;
        container.dataset.motionRunning = "false";
        return;
      }
      // Read geometry only on selection/resize, never inside the animation loop.
      const parentRect = container.getBoundingClientRect();
      const rect = selected.getBoundingClientRect();
      const target = [rect.left - parentRect.left - container.clientLeft + container.scrollLeft,
        rect.top - parentRect.top - container.clientTop + container.scrollTop, rect.width, rect.height];
      size = [Math.max(1, rect.width), Math.max(1, rect.height)];
      pill.style.width = `${size[0]}px`; pill.style.height = `${size[1]}px`;
      if (positioned) paint(values);
      pill.style.opacity = "1";
      pill.style.willChange = "transform";
      container.dataset.motionReady = "true";
      container.dataset.motionRunning = "true";
      motion.to(target, { immediate: immediate || !positioned });
      positioned = true;
    };
    refresh.current = measure;
    measure(true);
    const observer = new ResizeObserver(() => measure(true));
    observer.observe(container);
    container.querySelectorAll<HTMLElement>("[data-motion-item]").forEach(item => observer.observe(item));
    void document.fonts.ready.then(() => measure(true));
    return () => {
      disposed = true; observer.disconnect(); motion.dispose();
      channel.current = null; refresh.current = () => {};
    };
  }, []);

  useLayoutEffect(() => { refresh.current(); }, [activeKey, layoutKey]);

  return <Tag {...props} ref={root as Ref<HTMLDivElement>} className={`${styles.selection} ${className}`}>
    <span ref={surface} className={styles.indicator} data-motion-indicator aria-hidden="true" />
    {children}
  </Tag>;
}

/** A press can spring back while other controls continue moving. */
export function SpringButton({ children, disabled, onPointerDown, onPointerUp, onPointerLeave, onPointerCancel, onKeyDown, onKeyUp, onBlur, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  const element = useRef<HTMLButtonElement>(null);
  const channel = useRef<Channel | null>(null);
  useLayoutEffect(() => {
    const button = element.current;
    if (!button) return;
    const motion = createMotionChannel({
      read: () => [1], stiffness: 560, damping: 36,
      write: ([scale]) => { button.style.transform = `scale(${scale})`; },
      onRest: () => { button.style.willChange = "auto"; },
    });
    channel.current = motion;
    return () => { motion.dispose(); channel.current = null; };
  }, []);
  useLayoutEffect(() => { if (disabled) channel.current?.to([1], { immediate: true }); }, [disabled]);
  const press = (down: boolean) => {
    if (disabled) return;
    if (element.current) element.current.style.willChange = "transform";
    channel.current?.to([down ? .975 : 1]);
  };
  return <button {...props} ref={element} disabled={disabled} data-spring-button
    onPointerDown={event => { if (event.button === 0) press(true); onPointerDown?.(event); }}
    onPointerUp={event => { press(false); onPointerUp?.(event); }}
    onPointerLeave={event => { press(false); onPointerLeave?.(event); }}
    onPointerCancel={event => { press(false); onPointerCancel?.(event); }}
    onKeyDown={event => { if (event.key === " " || event.key === "Enter") press(true); onKeyDown?.(event); }}
    onKeyUp={event => { press(false); onKeyUp?.(event); }}
    onBlur={event => { press(false); onBlur?.(event); }}>{children}</button>;
}

/** New evidence appears immediately; only its visual settling is animated. */
export function MotionReveal({ motionKey, children, ...props }: HTMLAttributes<HTMLDivElement> & { motionKey: string }) {
  const element = useRef<HTMLDivElement>(null);
  const channel = useRef<Channel | null>(null);
  const current = useRef([1, 0]);
  useLayoutEffect(() => {
    const node = element.current;
    if (!node) return;
    const motion = createMotionChannel({
      read: () => current.current,
      write: values => {
        current.current = values;
        node.style.opacity = String(Math.min(1, Math.max(0, values[0])));
        node.style.transform = `translate3d(0,${values[1]}px,0)`;
      },
      onRest: () => { node.style.willChange = "auto"; },
    });
    channel.current = motion;
    return () => { motion.dispose(); channel.current = null; };
  }, []);
  useLayoutEffect(() => {
    const node = element.current;
    if (!node) return;
    node.style.willChange = "transform, opacity";
    if (current.current[1] < .01) channel.current?.to([.86, 5], { immediate: true });
    channel.current?.to([1, 0]);
  }, [motionKey]);
  return <div {...props} ref={element}>{children}</div>;
}

/**
 * Independent spring tracks, advanced together in one browser frame.
 * Retargeting preserves momentum instead of restarting or queuing transitions.
 * This is application-owned web motion, not an OxygenOS / OnePlus SDK.
 */
export type MotionChannelOptions = {
  read: () => number[];
  write: (values: number[]) => void;
  onRest?: () => void;
  stiffness?: number;
  damping?: number;
  mass?: number;
};

export type MotionChannel = {
  to: (target: number[], options?: { immediate?: boolean }) => void;
  stop: () => void;
  dispose: () => void;
};

type Track = {
  options: MotionChannelOptions;
  position: number[];
  velocity: number[];
  target: number[];
  stiffness: number;
  damping: number;
  mass: number;
  initialized: boolean;
  disposed: boolean;
  elapsed: number;
  version: number;
};

const active = new Set<Track>();
const maxDuration = 1.6;
let frame: number | null = null;
let lastTime: number | null = null;
let preference: MediaQueryList | null = null;
let observing = false;

function canAnimate() {
  return typeof window !== "undefined" && typeof document !== "undefined"
    && typeof window.requestAnimationFrame === "function" && !document.hidden
    && !(preference ?? window.matchMedia?.("(prefers-reduced-motion: reduce)"))?.matches;
}

function releaseObservers() {
  if (active.size) return;
  if (frame !== null && typeof window !== "undefined") window.cancelAnimationFrame(frame);
  frame = null;
  lastTime = null;
  if (!observing) return;
  document.removeEventListener("visibilitychange", onVisibilityChange);
  preference?.removeEventListener("change", onPreferenceChange);
  preference = null;
  observing = false;
}

function flushToTargets() {
  // Compute the complete batch first; a write callback may start a new track.
  const updates = [...active].map(track => {
    active.delete(track);
    track.position = [...track.target];
    track.velocity.fill(0);
    return { track, version: track.version, values: [...track.position] };
  });
  try {
    for (const { track, version, values } of updates) {
      if (track.disposed || track.version !== version) continue;
      track.options.write(values);
      if (!track.disposed && track.version === version) track.options.onRest?.();
    }
  } finally {
    releaseObservers();
  }
}

function onVisibilityChange() {
  if (document.hidden) flushToTargets();
}

function onPreferenceChange() {
  if (preference?.matches) flushToTargets();
}

function schedule() {
  if (!active.size) {
    releaseObservers();
    return;
  }
  if (!observing) {
    preference = window.matchMedia?.("(prefers-reduced-motion: reduce)") ?? null;
    document.addEventListener("visibilitychange", onVisibilityChange);
    preference?.addEventListener("change", onPreferenceChange);
    observing = true;
  }
  if (frame === null) frame = window.requestAnimationFrame(advance);
}

function advance(time: number) {
  frame = null;
  // Small substeps keep the same spring stable across 60/90/120Hz displays.
  // Clamp long frames so a suspended tab cannot launch a track across the UI.
  const delta = lastTime === null ? 1 / 60 : Math.min(Math.max((time - lastTime) / 1000, 0), 1 / 30);
  lastTime = time;
  const count = Math.max(1, Math.ceil(delta / (1 / 240)));
  const step = delta / count;
  const updates = [...active].map(track => {
    for (let n = 0; n < count; n++) {
      for (let i = 0; i < track.position.length; i++) {
        const force = track.stiffness * (track.target[i] - track.position[i]) - track.damping * track.velocity[i];
        track.velocity[i] += force / track.mass * step;
        track.position[i] += track.velocity[i] * step;
      }
    }
    track.elapsed += delta;
    const resting = track.elapsed >= maxDuration || track.position.every((value, i) =>
      Math.abs(value - track.target[i]) < .02 && Math.abs(track.velocity[i]) < .04);
    if (resting) {
      track.position = [...track.target];
      track.velocity.fill(0);
      active.delete(track);
    }
    return { track, values: [...track.position], version: track.version, resting };
  });
  // All physics is calculated before any DOM writes. No layout reads per frame.
  try {
    for (const { track, values, version, resting } of updates) {
      if (track.disposed || track.version !== version) continue;
      track.options.write(values);
      if (resting && !track.disposed && track.version === version) track.options.onRest?.();
    }
  } finally {
    schedule();
  }
}

function positive(value: number | undefined, fallback: number) {
  return value !== undefined && Number.isFinite(value) && value > 0 ? value : fallback;
}

function validate(values: number[]) {
  if (!values.length || !values.every(Number.isFinite)) throw new RangeError("Motion targets must be finite numeric vectors.");
}

export function createMotionChannel(options: MotionChannelOptions): MotionChannel {
  const track: Track = {
    options, position: [], velocity: [], target: [], initialized: false, disposed: false,
    stiffness: positive(options.stiffness, 420), damping: positive(options.damping, 38),
    mass: positive(options.mass, 1), elapsed: 0, version: 0,
  };
  const stop = () => {
    track.version++;
    track.velocity.fill(0);
    active.delete(track);
    releaseObservers();
  };
  return {
    to(target, settings) {
      if (track.disposed) return;
      validate(target);
      if (!track.initialized) {
        const initial = options.read();
        validate(initial);
        track.position = [...initial];
        track.velocity = initial.map(() => 0);
        track.initialized = true;
      }
      if (target.length !== track.position.length) throw new RangeError("Motion vector dimensions cannot change within a track.");
      const immediate = settings?.immediate || !canAnimate();
      if (!immediate && active.has(track) && target.every((value, i) => value === track.target[i])) return;
      track.version++;
      track.target = [...target];
      track.elapsed = 0;
      if (immediate || target.every((value, i) => value === track.position[i] && track.velocity[i] === 0)) {
        active.delete(track);
        track.position = [...target];
        track.velocity.fill(0);
        const version = track.version;
        try {
          options.write([...track.position]);
          if (!track.disposed && version === track.version) options.onRest?.();
        } finally {
          releaseObservers();
        }
        return;
      }
      active.add(track);
      schedule();
    },
    stop,
    dispose() {
      track.disposed = true;
      stop();
    },
  };
}

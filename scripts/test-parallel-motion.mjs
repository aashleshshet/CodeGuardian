import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createMotionChannel} from '../lib/parallel-motion.ts';

function environment() {
  let now = 0, id = 0, reduced = false;
  const frames = new Map(), visibility = new Set(), preference = new Set();
  const oldWindow = globalThis.window, oldDocument = globalThis.document;
  const media = {
    get matches() { return reduced; },
    addEventListener: (_, listener) => preference.add(listener),
    removeEventListener: (_, listener) => preference.delete(listener),
  };
  globalThis.window = {
    requestAnimationFrame(callback) {frames.set(++id, callback); return id;},
    cancelAnimationFrame(frame) {frames.delete(frame);},
    matchMedia: () => media,
  };
  globalThis.document = {
    hidden: false,
    addEventListener: (_, listener) => visibility.add(listener),
    removeEventListener: (_, listener) => visibility.delete(listener),
  };
  return {
    get pending() { return frames.size; },
    get listeners() { return visibility.size + preference.size; },
    step(ms = 1000 / 60) {now += ms; const callbacks = [...frames.values()]; frames.clear(); callbacks.forEach(callback => callback(now));},
    settle(ms = 1000 / 60) {for (let n = 0; n < 500 && frames.size; n++) this.step(ms); assert.equal(frames.size, 0, 'motion must become idle');},
    reduce(value) {reduced = value; [...preference].forEach(listener => listener());},
    hide() {globalThis.document.hidden = true; [...visibility].forEach(listener => listener());},
    restore() {globalThis.window = oldWindow; globalThis.document = oldDocument;},
  };
}

test('module is SSR safe and immediate tracks need no browser', () => {
  let rendered;
  const track = createMotionChannel({read: () => [0], write: values => {rendered = values;}});
  track.to([90]);
  assert.deepEqual(rendered, [90]);
  track.dispose();
});

test('independent tracks share a frame and settle without an idle RAF or listener', () => {
  const env = environment();
  const rendered = [[0, 0], [0]], rests = [0, 0];
  const tracks = rendered.map((value, i) => createMotionChannel({read: () => value, write: next => {rendered[i] = next;}, onRest: () => rests[i]++}));
  try {
    tracks[0].to([100, 40]); tracks[1].to([60]);
    assert.equal(env.pending, 1);
    env.step();
    assert.ok(rendered[0][0] > 0 && rendered[0][0] < 100);
    assert.ok(rendered[1][0] > 0 && rendered[1][0] < 60);
    assert.equal(env.pending, 1);
    env.settle();
    assert.deepEqual(rendered, [[100, 40], [60]]);
    assert.deepEqual(rests, [1, 1]);
    assert.equal(env.listeners, 0);
  } finally {tracks.forEach(track => track.dispose()); env.restore();}
});

test('a rapid reversal retains momentum and never jumps to a new starting position', () => {
  const env = environment(); let position = 0;
  const track = createMotionChannel({read: () => [0], write: ([value]) => {position = value;}});
  try {
    track.to([100]); env.step(); env.step(); env.step();
    const interrupted = position;
    track.to([0]);
    assert.equal(position, interrupted, 'retarget does not synchronously reset the visual');
    env.step();
    assert.ok(position > interrupted, 'existing velocity decelerates instead of resetting');
    env.settle(); assert.equal(position, 0);
  } finally {track.dispose(); env.restore();}
});

test('stopping or disposing one track does not block another track', () => {
  const env = environment(); let first = 0, second = 0, writes = 0;
  const a = createMotionChannel({read: () => [0], write: ([value]) => {first = value; writes++;}});
  const b = createMotionChannel({read: () => [0], write: ([value]) => {second = value;}});
  try {
    a.to([100]); b.to([300]); env.step(); a.stop();
    const frozen = first; env.step(); assert.equal(first, frozen);
    a.dispose(); const count = writes; a.to([50]); env.settle();
    assert.equal(writes, count); assert.equal(second, 300); assert.equal(env.listeners, 0);
  } finally {a.dispose(); b.dispose(); env.restore();}
});

test('live reduced-motion and hidden-tab changes finish active tracks and remove work', () => {
  const env = environment(); let position = 0;
  const track = createMotionChannel({read: () => [0], write: ([value]) => {position = value;}});
  try {
    track.to([100]); env.step(); env.reduce(true);
    assert.equal(position, 100); assert.equal(env.pending, 0); assert.equal(env.listeners, 0);
    track.to([25]); assert.equal(position, 25); assert.equal(env.pending, 0);
    env.reduce(false); track.to([90]); env.step(); env.hide();
    assert.equal(position, 90); assert.equal(env.pending, 0); assert.equal(env.listeners, 0);
    track.to([10]); assert.equal(position, 10); assert.equal(env.pending, 0);
  } finally {track.dispose(); env.restore();}
});

test('long frames remain bounded and high-refresh tracks converge to the exact target', () => {
  for (const interval of [1000 / 60, 1000 / 120, 1000 / 144]) {
    const env = environment(); let position = 0;
    const track = createMotionChannel({read: () => [0], write: ([value]) => {position = value;}});
    try {
      track.to([200]); env.step(interval); env.step(5000);
      assert.ok(Number.isFinite(position) && position > 0 && position < 200);
      env.settle(interval); assert.equal(position, 200);
    } finally {track.dispose(); env.restore();}
  }
});

test('callback retargeting cannot emit a stale completion or leave duplicate frames', () => {
  const env = environment(); let position = 0, rests = 0, retargeted = false;
  const track = createMotionChannel({read: () => [0], write: ([value]) => {
    position = value;
    if (value === 100 && !retargeted) {retargeted = true; track.to([50]);}
  }, onRest: () => rests++});
  try {
    track.to([100]); env.settle();
    assert.equal(position, 50); assert.equal(rests, 1); assert.equal(env.listeners, 0);
  } finally {track.dispose(); env.restore();}
});

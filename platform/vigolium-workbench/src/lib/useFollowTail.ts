'use client';

import { useCallback, useEffect, useRef } from 'react';

// Keeps a scrolling log view pinned to its newest line while the reader is at
// the bottom, and leaves it alone once they scroll up to read. Jumping to the
// bottom on every update made a running log impossible to read. A new
// resetKey (e.g. switching to another session) resumes following.
export function useFollowTail<T extends HTMLElement>(content: unknown, resetKey?: unknown) {
  const ref = useRef<T>(null);
  const follow = useRef(true);

  useEffect(() => {
    follow.current = true;
  }, [resetKey]);

  const onScroll = useCallback((e: React.UIEvent<T>) => {
    const el = e.currentTarget;
    follow.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (el && follow.current) el.scrollTop = el.scrollHeight;
  }, [content]);

  return { ref, onScroll };
}

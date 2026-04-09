import { useCallback, useEffect, useState } from 'react';

type ToastPayload = { id: number; message: string };

let idCounter = 0;
let pushToast: ((message: string) => void) | null = null;

/** Fire-and-forget notifications (rules: use only from services `onError` where inline errors are not used). */
export function toast(message: string): void {
  pushToast?.(message);
}

export function NdsToaster(): JSX.Element {
  const [items, setItems] = useState<ToastPayload[]>([]);

  const add = useCallback((message: string) => {
    const id = ++idCounter;
    setItems((prev) => [...prev, { id, message }]);
    window.setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, 4200);
  }, []);

  useEffect(() => {
    pushToast = add;
    return () => {
      pushToast = null;
    };
  }, [add]);

  if (items.length === 0) {
    return <></>;
  }

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 16,
        right: 16,
        zIndex: 2147483647,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        maxWidth: 320,
        pointerEvents: 'none'
      }}
      aria-live="polite"
    >
      {items.map((t) => (
        <div
          key={t.id}
          style={{
            background: '#0f172a',
            color: '#fff',
            padding: '10px 14px',
            borderRadius: 10,
            fontSize: 14,
            boxShadow: '0 8px 24px rgba(0,0,0,0.2)'
          }}
        >
          {t.message}
        </div>
      ))}
    </div>
  );
}

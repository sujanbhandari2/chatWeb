import type { ReactNode } from 'react';
import type { Message } from '../../types/chat';

export type DeliveryStatus = 'sent' | 'delivered' | 'seen';

export function PresenceDot({ online, title }: { online: boolean; title: string }): JSX.Element {
  return (
    <span
      className={`presence-dot ${online ? 'presence-dot--online' : 'presence-dot--offline'}`}
      title={title}
      aria-label={title}
      role="img"
    />
  );
}

export function AvatarWithPresence({ online, children }: { online: boolean; children: ReactNode }): JSX.Element {
  return (
    <div className="avatar-with-presence">
      {children}
      <PresenceDot online={online} title={online ? 'Online' : 'Offline'} />
    </div>
  );
}

export function IconSend(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={22} height={22} aria-hidden>
      <path fill="currentColor" d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
    </svg>
  );
}

export function IconAttach(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={22} height={22} aria-hidden>
      <path
        fill="currentColor"
        d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5c0-1.38 1.12-2.5 2.5-2.5s2.5 1.12 2.5 2.5v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5c0 1.38 1.12 2.5 2.5 2.5s2.5-1.12 2.5-2.5V5c0-2.21-1.79-4-4-4s-4 1.79-4 4v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"
      />
    </svg>
  );
}

export function IconImage(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={22} height={22} aria-hidden>
      <path
        fill="currentColor"
        d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"
      />
    </svg>
  );
}

/** Classic “REC” — outer ring + solid dot (reads clearly at small sizes). */
export function IconRecord(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={24} height={24} aria-hidden>
      <circle cx="12" cy="12" r="9.25" fill="none" stroke="currentColor" strokeWidth="1.65" opacity={0.4} />
      <circle cx="12" cy="12" r="5.25" fill="currentColor" />
    </svg>
  );
}

export function IconCheckSend(): JSX.Element {
  return (
    <svg className="composer-svg" viewBox="0 0 24 24" width={24} height={24} aria-hidden>
      <path
        fill="currentColor"
        d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"
      />
    </svg>
  );
}

export function formatRecordingDuration(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

export function getDeliveryStatus(message: Message): DeliveryStatus {
  const readReceipts = message.readReceipts ?? [];
  const deliveredReceipts = message.deliveredReceipts ?? [];

  const hasSeen = readReceipts.some((item) => item.userId !== message.senderId);
  if (hasSeen) {
    return 'seen';
  }

  const hasDelivered = deliveredReceipts.some((item) => item.userId !== message.senderId);
  if (hasDelivered) {
    return 'delivered';
  }

  return 'sent';
}

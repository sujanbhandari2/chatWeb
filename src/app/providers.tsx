import { QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { useEffect } from 'react';
import { NdsToaster } from '../common/nds/NdsToaster';
import { useAuthStore } from '../store/useAuthStore';
import { queryClient } from './query-client';

export function AppProviders({ children }: { children: ReactNode }): JSX.Element {
  const hydrate = useAuthStore((s) => s.hydrate);

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      <NdsToaster />
    </QueryClientProvider>
  );
}


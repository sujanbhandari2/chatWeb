import { QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { useEffect } from 'react';
import { NdsToaster } from '../common/ui/Toaster';
import { useAdminAuthStore } from '../store/useAdminAuthStore';
import { useAuthStore } from '../store/useAuthStore';
import { queryClient } from './query-client';

export function AppProviders({ children }: { children: ReactNode }): JSX.Element {
  const hydrate = useAuthStore((s) => s.hydrate);
  const hydrateAdmin = useAdminAuthStore((s) => s.hydrate);

  useEffect(() => {
    hydrate();
    hydrateAdmin();
  }, [hydrate, hydrateAdmin]);

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      <NdsToaster />
    </QueryClientProvider>
  );
}


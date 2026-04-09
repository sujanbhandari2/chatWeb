import type { ReactNode } from 'react';

export type GroupFormProps = {
  variant: 'create' | 'edit';
  children: ReactNode;
};

/** Section wrapper for inline create / edit group flows in the widget rail. */
export function GroupForm({ variant, children }: GroupFormProps): JSX.Element {
  const aria = variant === 'create' ? 'Create new group' : 'Edit group';
  return (
    <section className="widget-new-group-page" aria-label={aria}>
      {children}
    </section>
  );
}

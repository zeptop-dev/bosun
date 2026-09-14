import { notifications } from '@mantine/notifications'

let muted = false
// setToastMuted silences error toasts, e.g. while the panel restarts and
// every poll fails for a few seconds.
export const setToastMuted = (v: boolean) => { muted = v }

export const toast = {
  ok: (message: string) => notifications.show({ message, color: 'teal' }),
  err: (e: unknown) => { if (muted) return; notifications.show({ message: e instanceof Error ? e.message : String(e), color: 'red' }) },
}

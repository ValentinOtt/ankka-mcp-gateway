import type { CustomerBootstrapStatePort } from './customer-bootstrap-router';
import { markCustomerBootstrapReady, parseCustomerBootstrapState } from './customer-bootstrap-state';

export type CustomerBootstrapHandoverOutcome = 'ready' | 'idle';

/**
 * Run by the final runtime, from the alarm the bootstrap shell armed before
 * uploading it: an attempt the shell marked finalizing becomes READY. The
 * final runtime answering at all is the proof the shell could not journal,
 * since its upload restarted the object on this code. Idempotent; a
 * conflicting write means another pass already settled the attempt.
 */
export async function finalizeCustomerBootstrapHandover(
  state: CustomerBootstrapStatePort,
  now: number,
): Promise<CustomerBootstrapHandoverOutcome> {
  const stored = await state.read();
  const current = stored === undefined || stored === null ? null : parseCustomerBootstrapState(stored);
  if (current === null || current.status !== 'CONVERGING' || current.oauth?.phase !== 'finalizing') {
    return 'idle';
  }
  const ready = markCustomerBootstrapReady({ current, attemptId: current.oauth.attemptId, now });
  return await state.compareAndSet(current.revision, ready) ? 'ready' : 'idle';
}

import {
  CUSTOMER_BOOTSTRAP_CONVERGENCE_MAX_PASSES,
  continueCustomerBootstrapConvergence,
  type CustomerBootstrapConverge,
} from './customer-bootstrap-callback';
import type { CustomerBootstrapStatePort } from './customer-bootstrap-router';
import {
  markCustomerBootstrapIncomplete,
  parseCustomerBootstrapState,
  type CustomerBootstrapState,
} from './customer-bootstrap-state';
import type {
  CustomerCloudflareTransport,
  EphemeralCustomerCloudflareGrant,
} from './customer-cloudflare-grant';
import { CustomerStage2ConvergerError } from './customer-stage2-converger';

/** An attempt older than this settles INCOMPLETE on its next pass instead of running on. */
export const CUSTOMER_BOOTSTRAP_CONVERGENCE_DEADLINE_MS = 15 * 60 * 1_000;
/** How long after arming the handover the final runtime is expected to run its first pass. */
export const CUSTOMER_BOOTSTRAP_HANDOVER_ALARM_DELAY_MS = 8_000;

export interface CustomerBootstrapConvergenceDriverPorts {
  readonly state: CustomerBootstrapStatePort;
  readonly transport: CustomerCloudflareTransport;
  readonly publicClientId: string;
  readonly converge: CustomerBootstrapConverge;
  readonly now: () => number;
  /** Arranges for the next pass to run in a fresh invocation after `delayMs`. */
  readonly schedule: (delayMs: number) => Promise<void>;
}

export type CustomerBootstrapConvergenceStep = 'scheduled' | 'settled' | 'idle';

interface PendingConvergence {
  readonly attemptId: string;
  readonly grant: EphemeralCustomerCloudflareGrant;
  readonly startedAt: number;
  passes: number;
}

/**
 * Keeps the Stage 2 grant in object memory between converger passes so no
 * single invocation has to make every provider call. Storage never receives
 * the grant: an object restart between passes loses it, and the attempt then
 * settles INCOMPLETE with `grant_lost` rather than resuming from anything
 * durable. The journal and its lease make a repeated pass harmless.
 * A bounded timer prevents normal idle hibernation between alarms, including
 * when the browser is closed. It carries no credential and performs no work;
 * the alarm remains responsible for the next pass and deadline revocation.
 */
export class CustomerBootstrapConvergenceDriver {
  #pending: PendingConvergence | null = null;
  #retentionTimer: ReturnType<typeof setTimeout> | null = null;
  /** When this runtime handed the attempt over to the final runtime, if it did. */
  #handedOverAt: number | null = null;

  constructor(private readonly ports: CustomerBootstrapConvergenceDriverPorts) {}

  /** Takes the grant from a successful callback and schedules the first pass. */
  async start(input: {
    readonly attemptId: string;
    readonly grant: EphemeralCustomerCloudflareGrant;
  }): Promise<void> {
    this.forget();
    this.#pending = {
      attemptId: input.attemptId,
      grant: input.grant,
      startedAt: this.ports.now(),
      passes: 0,
    };
    this.#handedOverAt = null;
    this.#retentionTimer = setTimeout(() => {
      this.#retentionTimer = null;
    }, CUSTOMER_BOOTSTRAP_CONVERGENCE_DEADLINE_MS + 1);
    try {
      await this.ports.schedule(0);
    } catch (error) {
      this.releaseRetention();
      throw error;
    }
  }

  /** Runs one pass of the attempt the durable state names. */
  async continue(): Promise<CustomerBootstrapConvergenceStep> {
    const current = await this.readConverging();
    if (current === null) {
      this.forget();
      return 'idle';
    }
    const attemptId = current.oauth?.attemptId ?? null;
    if (current.oauth?.phase === 'finalizing') {
      // Handed over: the final runtime marks READY once the object restarts on
      // it. Until then this code only keeps a later look scheduled.
      this.forget();
      const handedOverAt = this.#handedOverAt ?? this.ports.now();
      this.#handedOverAt = handedOverAt;
      if (this.ports.now() - handedOverAt > CUSTOMER_BOOTSTRAP_CONVERGENCE_DEADLINE_MS) {
        await this.settle(current, attemptId, 'handover_timeout');
        return 'settled';
      }
      await this.ports.schedule(CUSTOMER_BOOTSTRAP_HANDOVER_ALARM_DELAY_MS);
      return 'scheduled';
    }
    const pending = this.#pending;
    if (pending === null || attemptId === null || pending.attemptId !== attemptId) {
      this.forget();
      await this.settle(current, attemptId, 'grant_lost');
      return 'settled';
    }
    pending.passes += 1;
    const overdue = this.ports.now() - pending.startedAt > CUSTOMER_BOOTSTRAP_CONVERGENCE_DEADLINE_MS;
    const exhausted = pending.passes > CUSTOMER_BOOTSTRAP_CONVERGENCE_MAX_PASSES;
    const converge: CustomerBootstrapConverge = overdue || exhausted
      ? async () => {
        throw new CustomerStage2ConvergerError(
          'provider_mismatch',
          overdue ? 'convergence_deadline' : 'convergence_passes_exhausted',
        );
      }
      : this.ports.converge;
    let outcome: Awaited<ReturnType<typeof continueCustomerBootstrapConvergence>>;
    try {
      outcome = await continueCustomerBootstrapConvergence({
        current,
        attemptId,
        grant: pending.grant,
        publicClientId: this.ports.publicClientId,
        now: this.ports.now(),
        transport: this.ports.transport,
        persist: (expected, next) => this.persist(expected, next),
        converge,
        armHandover: () => this.ports.schedule(CUSTOMER_BOOTSTRAP_HANDOVER_ALARM_DELAY_MS),
      });
    } catch {
      // A durable conflict or a thrown port: the grant is dropped so nothing
      // keeps it alive, and the attempt is named as stopped for a fresh start.
      this.forget();
      await this.settle(current, attemptId, 'unexpected');
      return 'settled';
    }
    if (outcome.status === 'CONVERGING') {
      await this.ports.schedule(0);
      return 'scheduled';
    }
    if (outcome.status === 'HANDED_OVER') this.#handedOverAt = this.ports.now();
    this.forget();
    return 'settled';
  }

  private releaseRetention(): void {
    if (this.#retentionTimer !== null) clearTimeout(this.#retentionTimer);
    this.#retentionTimer = null;
  }

  private forget(): void {
    this.releaseRetention();
    this.#pending?.grant.discard();
    this.#pending = null;
  }

  private async readConverging(): Promise<CustomerBootstrapState | null> {
    const stored = await this.ports.state.read();
    const current = stored === undefined || stored === null ? null : parseCustomerBootstrapState(stored);
    return current !== null && current.status === 'CONVERGING' ? current : null;
  }

  private async persist(expected: CustomerBootstrapState, next: CustomerBootstrapState): Promise<void> {
    if (next.revision !== expected.revision + 1 ||
        !await this.ports.state.compareAndSet(expected.revision, next)) {
      throw new Error('customer_bootstrap_state_conflict');
    }
  }

  private async settle(
    current: CustomerBootstrapState,
    attemptId: string | null,
    reason: string,
  ): Promise<void> {
    if (attemptId === null) return;
    try {
      const incomplete = markCustomerBootstrapIncomplete({
        current,
        attemptId,
        failureCode: 'revocation_unconfirmed',
        failureReason: reason,
      });
      await this.persist(current, incomplete);
    } catch {
      // A concurrent writer already moved the attempt on; its record stands.
    }
  }
}

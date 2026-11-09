export interface Criterion<T = unknown> {
  name: string;
  weight: number;
  term: (candidate: T) => number;
}

export class CommitmentGate {
  constructor(statesCount: number, minDwellTime: number, defaultCooldown?: number);
  readonly state: number;
  readonly minDwell: number;
  readonly accepted: number;
  readonly rejected: number;
  setCooldown(state: number, seconds: number): void;
  setExempt(state: number, exempt: boolean): void;
  allowed(next: number, now: number): boolean;
  tryTransition(next: number, now: number): boolean;
}

export class Commitment {
  constructor(lifetime: number, lockWindow: number);
  readonly score: number;
  readonly committed: boolean;
  isExpired(now: number): boolean;
  isLocked(now: number): boolean;
  shouldReplace(challengerScore: number, margin: number, now: number): boolean;
  adopt(score: number, now: number): void;
  clear(): void;
}

export class PluralityConsensus {
  constructor(classesCount: number, capacity?: number, freshnessWindow?: number, minVotesCount?: number);
  readonly value: number;
  readonly settled: boolean;
  vote(voterId: number, classIndex: number, now: number): boolean;
  resolve(now: number): boolean;
}

export class ClaimTable {
  constructor(slotsCount: number);
  readonly slots: number;
  occupancy(now: number): number;
  tryClaim(holderId: number, bid: number, lifetime: number, now: number, capacity: number): boolean;
  release(holderId: number): void;
}

export class PartitionAssignment {
  constructor(partitionsCount: number);
  tryAssign(agentId: number, preferred: number, lifetime: number, now: number): { success: boolean; partition: number };
  release(agentId: number): void;
}

export class WeightedScorer<T = unknown> {
  constructor(criteria: Criterion<T>[]);
  score(candidate: T): number;
  trySelect(candidateCount: number, threshold?: number, bias?: number): { success: boolean; best: number; score: number };
}

export class SynchronizationBarrier {
  constructor(capacity?: number);
  readonly reachedQuorum: boolean;
  reportReady(agentId: number, now: number): void;
  tick(population: number, quorumThreshold?: number, timeoutSeconds?: number, now?: number): boolean;
  reset(): void;
}

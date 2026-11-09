export class CommitmentGate {
  constructor(statesCount, minDwellTime, defaultCooldown = 0.0) {
    if (statesCount < 1) throw new RangeError("statesCount must be at least 1");
    if (minDwellTime < 0.0) throw new RangeError("minDwellTime cannot be negative");

    this.statesCount = statesCount;
    this.minDwellTime = minDwellTime;
    this.cooldowns = new Float64Array(statesCount);
    this.lastEntries = new Float64Array(statesCount);
    this.exemptions = new Uint8Array(statesCount);

    for (let i = 0; i < statesCount; i++) {
      this.cooldowns[i] = defaultCooldown;
      this.lastEntries[i] = -Infinity;
    }

    this.currentState = 0;
    this.enteredAtTime = 0.0;
    this.acceptedTransitions = 0;
    this.rejectedTransitions = 0;
  }

  get state() {
    return this.currentState;
  }

  get minDwell() {
    return this.minDwellTime;
  }

  get accepted() {
    return this.acceptedTransitions;
  }

  get rejected() {
    return this.rejectedTransitions;
  }

  setCooldown(state, seconds) {
    if (state < 0 || state >= this.statesCount) return;
    this.cooldowns[state] = seconds;
  }

  setExempt(state, exempt) {
    if (state < 0 || state >= this.statesCount) return;
    this.exemptions[state] = exempt ? 1 : 0;
  }

  allowed(next, now) {
    if (next < 0 || next >= this.statesCount) return false;
    if (next === this.currentState) return false;
    if (this.exemptions[next] !== 0) return true;
    if (this.cooldowns[next] > 0.0 && now - this.lastEntries[next] < this.cooldowns[next]) return false;
    return now - this.enteredAtTime >= this.minDwellTime;
  }

  tryTransition(next, now) {
    if (!this.allowed(next, now)) {
      this.rejectedTransitions++;
      return false;
    }

    this.currentState = next;
    this.enteredAtTime = now;
    this.lastEntries[next] = now;
    this.acceptedTransitions++;
    return true;
  }
}

export class Commitment {
  constructor(lifetime, lockWindow) {
    if (lifetime <= 0.0) throw new RangeError("lifetime must be positive");
    if (lockWindow < 0.0) throw new RangeError("lockWindow cannot be negative");

    this.lifetime = lifetime;
    this.lockWindow = lockWindow;
    this.adoptedAt = -Infinity;
    this.currentScore = 0.0;
    this.hasCommitment = false;
  }

  get score() {
    return this.currentScore;
  }

  get committed() {
    return this.hasCommitment;
  }

  isExpired(now) {
    return !this.hasCommitment || now - this.adoptedAt >= this.lifetime;
  }

  isLocked(now) {
    return this.hasCommitment && now - this.adoptedAt < this.lockWindow;
  }

  shouldReplace(challengerScore, margin, now) {
    if (this.isExpired(now)) return true;
    if (this.isLocked(now)) return false;
    return challengerScore >= this.currentScore + margin;
  }

  adopt(score, now) {
    this.currentScore = score;
    this.adoptedAt = now;
    this.hasCommitment = true;
  }

  clear() {
    this.hasCommitment = false;
    this.currentScore = 0.0;
    this.adoptedAt = -Infinity;
  }
}

export class PluralityConsensus {
  constructor(classesCount, capacity = 16, freshnessWindow = 6.0, minVotesCount = 1) {
    if (classesCount < 1) throw new RangeError("classesCount must be at least 1");
    if (capacity < 1) throw new RangeError("capacity must be at least 1");
    if (freshnessWindow <= 0.0) throw new RangeError("freshnessWindow must be positive");
    if (minVotesCount < 1) throw new RangeError("minVotesCount must be at least 1");

    this.classesCount = classesCount;
    this.capacity = capacity;
    this.freshnessWindow = freshnessWindow;
    this.minVotesCount = minVotesCount;
    this.voterIds = new Int32Array(capacity);
    this.voterClasses = new Int32Array(capacity);
    this.voterTimes = new Float64Array(capacity);
    this.tallies = new Int32Array(classesCount);
    this.agreedValue = 0;
    this.isSettled = false;
  }

  get value() {
    return this.agreedValue;
  }

  get settled() {
    return this.isSettled;
  }

  vote(voterId, classIndex, now) {
    if (voterId === 0 || classIndex < 0 || classIndex >= this.classesCount) return false;

    for (let i = 0; i < this.capacity; i++) {
      if (this.voterIds[i] === voterId) {
        this.voterClasses[i] = classIndex;
        this.voterTimes[i] = now;
        return true;
      }
    }

    for (let i = 0; i < this.capacity; i++) {
      const live = this.voterIds[i] !== 0 && now - this.voterTimes[i] < this.freshnessWindow;
      if (!live) {
        this.voterIds[i] = voterId;
        this.voterClasses[i] = classIndex;
        this.voterTimes[i] = now;
        return true;
      }
    }

    return false;
  }

  resolve(now) {
    this.tallies.fill(0);
    let totalLive = 0;

    for (let i = 0; i < this.capacity; i++) {
      if (this.voterIds[i] !== 0 && now - this.voterTimes[i] < this.freshnessWindow) {
        const c = this.voterClasses[i];
        if (c >= 0 && c < this.classesCount) {
          this.tallies[c]++;
          totalLive++;
        }
      }
    }

    if (totalLive < this.minVotesCount) {
      this.isSettled = false;
      return false;
    }

    let topVotes = 0;
    let topClass = 0;
    let tie = false;

    for (let c = 0; c < this.classesCount; c++) {
      const v = this.tallies[c];
      if (v > topVotes) {
        topVotes = v;
        topClass = c;
        tie = false;
      } else if (v === topVotes && topVotes > 0) {
        tie = true;
      }
    }

    if (topVotes >= this.minVotesCount && !tie) {
      this.agreedValue = topClass;
      this.isSettled = true;
      return true;
    }

    this.isSettled = false;
    return false;
  }
}

export class ClaimTable {
  constructor(slotsCount) {
    if (slotsCount < 1) throw new RangeError("slotsCount must be at least 1");
    this.slotsCount = slotsCount;
    this.holders = new Int32Array(slotsCount);
    this.expirationTimes = new Float64Array(slotsCount);
    this.bids = new Float64Array(slotsCount);
  }

  get slots() {
    return this.slotsCount;
  }

  occupancy(now) {
    let n = 0;
    for (let i = 0; i < this.slotsCount; i++) {
      if (this.holders[i] !== 0 && now < this.expirationTimes[i]) n++;
    }
    return n;
  }

  tryClaim(holderId, bid, lifetime, now, capacity) {
    if (holderId === 0 || capacity < 1 || lifetime <= 0.0) return false;

    for (let i = 0; i < this.slotsCount; i++) {
      if (this.holders[i] === holderId) {
        this.expirationTimes[i] = now + lifetime;
        this.bids[i] = bid;
        return true;
      }
    }

    let used = 0;
    let freeIndex = -1;
    let weakestIndex = -1;
    let weakestBid = Infinity;

    for (let i = 0; i < this.slotsCount; i++) {
      const live = this.holders[i] !== 0 && now < this.expirationTimes[i];
      if (!live) {
        if (freeIndex < 0) freeIndex = i;
        continue;
      }
      used++;
      if (this.bids[i] < weakestBid) {
        weakestBid = this.bids[i];
        weakestIndex = i;
      }
    }

    if (used < capacity && freeIndex >= 0) {
      this.holders[freeIndex] = holderId;
      this.expirationTimes[freeIndex] = now + lifetime;
      this.bids[freeIndex] = bid;
      return true;
    }

    if (weakestIndex >= 0 && bid > weakestBid) {
      this.holders[weakestIndex] = holderId;
      this.expirationTimes[weakestIndex] = now + lifetime;
      this.bids[weakestIndex] = bid;
      return true;
    }

    return false;
  }

  release(holderId) {
    for (let i = 0; i < this.slotsCount; i++) {
      if (this.holders[i] === holderId) {
        this.holders[i] = 0;
        this.expirationTimes[i] = 0.0;
        this.bids[i] = 0.0;
      }
    }
  }
}

export class PartitionAssignment {
  constructor(partitionsCount) {
    if (partitionsCount < 1) throw new RangeError("partitionsCount must be at least 1");
    this.partitionsCount = partitionsCount;
    this.assignments = new Int32Array(partitionsCount);
    this.expirationTimes = new Float64Array(partitionsCount);
  }

  tryAssign(agentId, preferred, lifetime, now) {
    if (agentId === 0 || lifetime <= 0.0) return { success: false, partition: -1 };

    for (let i = 0; i < this.partitionsCount; i++) {
      if (this.assignments[i] === agentId && now < this.expirationTimes[i]) {
        this.expirationTimes[i] = now + lifetime;
        return { success: true, partition: i };
      }
    }

    const normPref = ((preferred % this.partitionsCount) + this.partitionsCount) % this.partitionsCount;

    for (let step = 0; step <= Math.floor(this.partitionsCount / 2); step++) {
      const candidates = step === 0 ? [normPref] : [
        (normPref + step) % this.partitionsCount,
        ((normPref - step) % this.partitionsCount + this.partitionsCount) % this.partitionsCount
      ];

      for (const p of candidates) {
        const live = this.assignments[p] !== 0 && now < this.expirationTimes[p];
        if (!live) {
          this.assignments[p] = agentId;
          this.expirationTimes[p] = now + lifetime;
          return { success: true, partition: p };
        }
      }
    }

    return { success: false, partition: -1 };
  }

  release(agentId) {
    for (let i = 0; i < this.partitionsCount; i++) {
      if (this.assignments[i] === agentId) {
        this.assignments[i] = 0;
        this.expirationTimes[i] = 0.0;
      }
    }
  }
}

export class WeightedScorer {
  constructor(criteria) {
    if (!Array.isArray(criteria) || criteria.length === 0) throw new TypeError("criteria must be non-empty array");
    this.criteria = criteria;
    let m = 0.0;
    for (const c of this.criteria) {
      if (!c || typeof c.term !== "function") throw new TypeError("criterion or term cannot be null");
      m += Number(c.weight || 0);
    }
    if (m <= 0.0) throw new RangeError("total weight must be positive");
    this.totalWeight = m;
  }

  score(candidate) {
    let s = 0.0;
    for (const c of this.criteria) {
      let f = c.term(candidate);
      if (f < 0.0) f = 0.0;
      else if (f > 1.0) f = 1.0;
      s += c.weight * f;
    }
    return s / this.totalWeight;
  }

  trySelect(candidateCount, threshold = 0.5, bias = 1.0) {
    if (candidateCount < 1 || bias <= 0.0) return { success: false, best: -1, score: 0.0 };

    const effectiveThreshold = threshold / bias;
    let bestIndex = -1;
    let bestScore = -1.0;

    for (let i = 0; i < candidateCount; i++) {
      const s = this.score(i);
      if (s > bestScore) {
        bestScore = s;
        bestIndex = i;
      }
    }

    if (bestScore >= effectiveThreshold && bestIndex >= 0) {
      return { success: true, best: bestIndex, score: bestScore };
    }

    return { success: false, best: bestIndex, score: bestScore };
  }
}

export class SynchronizationBarrier {
  constructor(capacity = 16) {
    if (capacity < 1) throw new RangeError("capacity must be at least 1");
    this.capacity = capacity;
    this.agentIds = new Int32Array(capacity);
    this.readyStates = new Uint8Array(capacity);
    this.reportTimes = new Float64Array(capacity);
    this.quorumReached = false;
    this.stageStartTime = 0.0;
  }

  get reachedQuorum() {
    return this.quorumReached;
  }

  reportReady(agentId, now) {
    if (agentId === 0) return;
    for (let i = 0; i < this.capacity; i++) {
      if (this.agentIds[i] === agentId || this.agentIds[i] === 0) {
        this.agentIds[i] = agentId;
        this.readyStates[i] = 1;
        this.reportTimes[i] = now;
        return;
      }
    }
  }

  tick(population, quorumThreshold = 0.6, timeoutSeconds = 10.0, now = 0.0) {
    if (population < 1) return false;
    const required = Math.ceil(population * quorumThreshold);

    let readyCount = 0;
    for (let i = 0; i < this.capacity; i++) {
      if (this.agentIds[i] !== 0 && this.readyStates[i] === 1) {
        readyCount++;
      }
    }

    if (this.stageStartTime === 0.0) this.stageStartTime = now;

    if (readyCount >= required) {
      this.quorumReached = true;
      return true;
    }

    if (now - this.stageStartTime >= timeoutSeconds) {
      this.quorumReached = false;
      return true;
    }

    return false;
  }

  reset() {
    this.agentIds.fill(0);
    this.readyStates.fill(0);
    this.reportTimes.fill(0.0);
    this.quorumReached = false;
    this.stageStartTime = 0.0;
  }
}

const assert = require("node:assert/strict");

async function run() {
  const {
    CommitmentGate,
    Commitment,
    PluralityConsensus,
    ClaimTable,
    PartitionAssignment,
    WeightedScorer,
    SynchronizationBarrier
  } = await import("../src/decision/index.js");

  const gate = new CommitmentGate(3, 2.0, 1.0);
  assert.equal(gate.state, 0);
  assert.equal(gate.tryTransition(1, 1.0), false);
  assert.equal(gate.tryTransition(1, 2.5), true);
  assert.equal(gate.state, 1);

  const commitment = new Commitment(5.0, 2.0);
  commitment.adopt(0.8, 10.0);
  assert.equal(commitment.shouldReplace(0.9, 0.05, 11.0), false);
  assert.equal(commitment.shouldReplace(0.86, 0.05, 13.0), true);
  assert.equal(commitment.shouldReplace(0.82, 0.05, 13.0), false);

  const consensus = new PluralityConsensus(4, 8, 5.0, 2);
  consensus.vote(101, 2, 1.0);
  consensus.vote(102, 2, 1.1);
  consensus.vote(103, 1, 1.2);
  assert.equal(consensus.resolve(1.5), true);
  assert.equal(consensus.value, 2);
  assert.equal(consensus.settled, true);

  const claim = new ClaimTable(4);
  assert.equal(claim.tryClaim(501, 10.0, 5.0, 1.0, 2), true);
  assert.equal(claim.tryClaim(502, 20.0, 5.0, 1.0, 2), true);
  assert.equal(claim.tryClaim(503, 5.0, 5.0, 1.0, 2), false);
  assert.equal(claim.tryClaim(504, 30.0, 5.0, 1.0, 2), true);
  assert.equal(claim.occupancy(1.0), 2);

  const partitions = new PartitionAssignment(4);
  const p1 = partitions.tryAssign(10, 0, 5.0, 1.0);
  assert.equal(p1.success, true);
  assert.equal(p1.partition, 0);
  const p2 = partitions.tryAssign(20, 0, 5.0, 1.0);
  assert.equal(p2.success, true);
  assert.equal(p2.partition, 1);

  const scorer = new WeightedScorer([
    { name: "termA", weight: 2.0, term: (x) => (x > 5 ? 1.0 : 0.0) },
    { name: "termB", weight: 1.0, term: (x) => (x % 2 === 0 ? 1.0 : 0.0) }
  ]);
  assert.equal(scorer.score(6), 1.0);
  assert.equal(scorer.score(4), 1.0 / 3.0);
  const sel = scorer.trySelect(10, 0.5);
  assert.equal(sel.success, true);

  const barrier = new SynchronizationBarrier(4);
  barrier.reportReady(1, 1.0);
  barrier.reportReady(2, 1.1);
  assert.equal(barrier.tick(3, 0.6, 5.0, 1.2), true);
  assert.equal(barrier.reachedQuorum, true);

  console.log("All DecisionCore unit tests passed successfully.");
}

void run();

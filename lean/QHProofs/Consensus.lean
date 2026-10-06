/-
  QHProofs.Consensus

  Integer counting lemmas for BFT quorum arithmetic (strict > 2n/3 form).

  Honest description: six short `omega` lemmas on natural numbers.
  There is no model of validators, votes, blocks, or heights in this file,
  and the threshold used is the STRICT inequality q*3 > n*2, which differs
  from the deployed ⌈2N/3⌉ rule when N is divisible by 3 (at N = 3: strict
  needs 3 votes, ⌈2N/3⌉ needs 2). For the certificate-level finality-safety
  theorem for the exact deployed rule, see QHProofs.FinalityModel.
-/

import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Linarith

namespace QHProofs.Consensus

/-! ## BFT quorum intersection

    Core lemma: if two subsets of {1, ..., n} each have more than 2n/3 elements,
    their intersection has more than n/3 elements. This is a counting argument. -/

/-- If Q₁ > 2n/3 and Q₂ > 2n/3, then Q₁ ∩ Q₂ > n/3 (by inclusion-exclusion).
    |Q₁| + |Q₂| - |Q₁ ∪ Q₂| = |Q₁ ∩ Q₂|
    |Q₁ ∪ Q₂| ≤ n
    So |Q₁ ∩ Q₂| ≥ |Q₁| + |Q₂| - n > 2n/3 + 2n/3 - n = n/3. -/
theorem bft_no_two_quorums_disagree (n q₁ q₂ : ℕ) (_hn : n ≥ 1)
    (hq₁ : q₁ * 3 > n * 2) (hq₂ : q₂ * 3 > n * 2)
    (hq₁_le : q₁ ≤ n) (_hq₂_le : q₂ ≤ n) :
    (q₁ + q₂ - n) * 3 > n := by omega

/-- If honest > 2n/3 and quorum > 2n/3, their overlap > n/3,
    so the quorum must contain at least one honest node. -/
theorem bft_quorum_has_honest (n honest quorum : ℕ) (_hn : n ≥ 1)
    (h_honest : honest * 3 > n * 2) (h_quorum : quorum * 3 > n * 2)
    (_h_honest_le : honest ≤ n) (_h_quorum_le : quorum ≤ n) :
    honest + quorum > n := by omega

/-- Integer form only: two strict quorums out of n overlap in more members
    than the Byzantine count. No certificates, blocks, or heights appear
    here; for the certificate-level uniqueness statement see
    `QHProofs.FinalityModel.finality_unique`. -/
theorem quorum_overlap_exceeds_byzantine (n q₁ q₂ byzantine : ℕ) (_hn : n ≥ 1)
    (hq₁ : q₁ * 3 > n * 2) (hq₂ : q₂ * 3 > n * 2)
    (hq₁_le : q₁ ≤ n) (_hq₂_le : q₂ ≤ n)
    (h_byz : byzantine * 3 < n) :
    q₁ + q₂ - n > byzantine := by omega

/-- 2n/3 > n/2 for n ≥ 1: supermajority implies simple majority.
    Encoded as: if q * 3 > n * 2, then q * 2 > n. -/
theorem supermajority_gt_half (n q : ℕ) (_hn : n ≥ 1)
    (hq : q * 3 > n * 2) : q * 2 > n := by omega

/-- Maximum byzantine fraction for safety: byzantine < n/3. -/
theorem max_byzantine_fraction (n byzantine : ℕ) (hn : n ≥ 1)
    (h : byzantine * 3 < n) : byzantine < n := by omega

/-- A valid certificate has > 2n/3 signatures. -/
theorem certificate_vote_count (n votes : ℕ) (hn : n ≥ 1)
    (h : votes * 3 > n * 2) : votes ≥ 1 := by omega

end QHProofs.Consensus

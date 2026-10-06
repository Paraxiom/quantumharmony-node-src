/-
  QHProofs.FinalityModel

  A certificate-level finality-safety theorem for the deployed quorum rule.

  Unlike `QHProofs.Consensus` (integer counting lemmas on bare naturals), this
  module has an actual model: validators, a vote relation, a Byzantine set, an
  honest-single-vote assumption, and certificates. The main theorem,
  `finality_unique`, states that two certificates at the same height name the
  same block — for the EXACT deployed threshold ⌈2N/3⌉ (computed in ℕ as
  (2*N + 2) / 3), under the assumption 3f < N.

  Honest scope, stated plainly:
    * Model-level. No refinement connects this model to the Rust gadget.
    * Safety only. Nothing here says finality ever happens (no liveness).
    * At N = 3 the hypothesis 3f < N forces f = 0: the theorem covers N = 3
      only with zero Byzantine validators. Byzantine tolerance (f = 1) begins
      at N = 4. This is a fact about the rule, not a weakness of the proof.

  Zero `sorry`. No axioms beyond Lean's standard base via Mathlib.
-/

import Mathlib

namespace QHProofs.FinalityModel

/-- The deployed quorum threshold ⌈2n/3⌉, computed in ℕ as (2n + 2) / 3.
    (Check: n = 3 → 2; n = 4 → 3; n = 6 → 4; n = 7 → 5.) -/
def quorum (n : ℕ) : ℕ := (2 * n + 2) / 3

/-- The voting model at one height: who voted for what, and who is Byzantine.
    Honest validators vote for at most one block; Byzantine validators are
    unconstrained (they may equivocate freely). -/
structure Setting (n : ℕ) (Block : Type*) where
  /-- The vote relation: `votes v b` means validator `v` cast a vote for `b`. -/
  votes : Fin n → Block → Prop
  /-- The Byzantine validators. -/
  byz : Finset (Fin n)
  /-- Strictly fewer than a third of validators are Byzantine. -/
  hbyz : 3 * byz.card < n
  /-- An honest validator votes for at most one block at this height. -/
  honest_single :
    ∀ v : Fin n, v ∉ byz → ∀ b b' : Block, votes v b → votes v b' → b = b'

/-- A finality certificate for block `b`: at least ⌈2n/3⌉ distinct validators,
    each of whom voted for `b`. -/
structure Certificate {n : ℕ} {Block : Type*} (S : Setting n Block) (b : Block) where
  voters : Finset (Fin n)
  hcard : quorum n ≤ voters.card
  hvoted : ∀ v ∈ voters, S.votes v b

/-- **Finality safety for the deployed rule.** Two certificates at the same
    height name the same block: their voter sets overlap in more validators
    than there are Byzantine ones, so an honest validator signed both, and an
    honest validator votes only once. -/
theorem finality_unique {n : ℕ} {Block : Type*} (S : Setting n Block)
    {b₁ b₂ : Block} (c₁ : Certificate S b₁) (c₂ : Certificate S b₂) :
    b₁ = b₂ := by
  -- |V₁ ∩ V₂| + |V₁ ∪ V₂| = |V₁| + |V₂|, and |V₁ ∪ V₂| ≤ n.
  have hie := Finset.card_inter_add_card_union c₁.voters c₂.voters
  have hu : (c₁.voters ∪ c₂.voters).card ≤ n := by
    simpa [Fintype.card_fin] using Finset.card_le_univ (c₁.voters ∪ c₂.voters)
  -- The intersection is larger than the Byzantine set.
  have hover : S.byz.card < (c₁.voters ∩ c₂.voters).card := by
    have h₁ := c₁.hcard
    have h₂ := c₂.hcard
    have hb := S.hbyz
    unfold quorum at h₁ h₂
    omega
  -- Hence some voter in both certificates is honest.
  have hnot : ¬ (c₁.voters ∩ c₂.voters) ⊆ S.byz := by
    intro hsub
    exact absurd (Finset.card_le_card hsub) (not_le.mpr hover)
  obtain ⟨v, hv, hvb⟩ := Finset.not_subset.mp hnot
  have hv₁ : v ∈ c₁.voters := (Finset.mem_inter.mp hv).1
  have hv₂ : v ∈ c₂.voters := (Finset.mem_inter.mp hv).2
  -- The honest voter voted for both blocks, so they are equal.
  exact S.honest_single v hvb b₁ b₂ (c₁.hvoted v hv₁) (c₂.hvoted v hv₂)

/-- At N = 3 the Byzantine hypothesis forces f = 0: the deployed 2-of-3 rule
    is safe only with zero Byzantine validators. Byzantine tolerance begins
    at N = 4. Stated as a theorem so the paper's claim is checkable. -/
theorem n3_forces_f0 {Block : Type*} (S : Setting 3 Block) : S.byz.card = 0 := by
  have := S.hbyz
  omega

end QHProofs.FinalityModel

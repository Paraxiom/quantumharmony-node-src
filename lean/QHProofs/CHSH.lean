/-
  QHProofs.CHSH

  The classical CHSH (Bell) bound, mechanized.

  Key results:
    - chsh_pointwise      — for ±1 outcomes, the CHSH value lies in [-2, 2]
    - chsh_abs_pointwise  — |CHSH value| ≤ 2 (pointwise)
    - chsh_classical      — |E[CHSH]| ≤ 2 for any finite local (hidden-variable)
                            distribution over deterministic ±1 responses

  Scope, stated plainly: this is the elementary classical bound and nothing
  more. It does not formalize the Tsirelson bound, the convexity reduction of
  stochastic strategies, or any quantum object. Substantially deeper CHSH
  formalization exists (Zhao & Yu, "Formalizing CHSH Rigidity in Lean 4",
  arXiv:2604.03884); this file is the floor of that edifice.

  Zero `sorry`. No axioms beyond Lean's standard base via Mathlib.
-/

import Mathlib

namespace QHProofs.CHSH

/-- The CHSH correlator value for a single deterministic assignment of the four
    ±1 observables `a, a', b, b'`. -/
def chsh (a a' b b' : ℝ) : ℝ := a * b - a * b' + a' * b + a' * b'

/-- **Pointwise CHSH bound.** For any assignment of `±1` values to the four
    observables, the CHSH value lies in the interval `[-2, 2]`.

    Proof: `a(b - b') + a'(b + b')`; for `b, b' ∈ {-1, 1}` exactly one of
    `(b - b')` and `(b + b')` is `0` and the other is `±2`, so the whole
    expression is `±2`. Verified here by exhaustion over the 16 cases. -/
theorem chsh_pointwise (a a' b b' : ℝ)
    (ha : a = 1 ∨ a = -1) (ha' : a' = 1 ∨ a' = -1)
    (hb : b = 1 ∨ b = -1) (hb' : b' = 1 ∨ b' = -1) :
    chsh a a' b b' ≤ 2 ∧ -2 ≤ chsh a a' b b' := by
  unfold chsh
  rcases ha with rfl | rfl <;> rcases ha' with rfl | rfl <;>
    rcases hb with rfl | rfl <;> rcases hb' with rfl | rfl <;>
    constructor <;> norm_num

/-- `|CHSH value| ≤ 2` for any `±1` assignment. -/
theorem chsh_abs_pointwise (a a' b b' : ℝ)
    (ha : a = 1 ∨ a = -1) (ha' : a' = 1 ∨ a' = -1)
    (hb : b = 1 ∨ b = -1) (hb' : b' = 1 ∨ b' = -1) :
    |chsh a a' b b'| ≤ 2 := by
  have h := chsh_pointwise a a' b b' ha ha' hb hb'
  rw [abs_le]
  exact ⟨h.2, h.1⟩

/-- **Classical (local hidden variable) CHSH bound.** For any finite probability
    distribution `p` over hidden states `ι`, and any `±1`-valued local response
    functions `A, A', B, B'`, the expected CHSH value satisfies `|E[CHSH]| ≤ 2`.

    This is the bound no local classical strategy can beat in expectation.
    Scope: an *observed* `S > 2` indicates correlations outside the LHV class
    only when the CHSH assumptions are enforced (settings independent of the
    devices, no cross-wing communication, no post-selection); without loophole
    control it is just a reported number. Finite-sample estimates can also
    exceed the bound by fluctuation. -/
theorem chsh_classical {ι : Type*} [Fintype ι]
    (p A A' B B' : ι → ℝ)
    (hp0 : ∀ i, 0 ≤ p i) (hp1 : ∑ i, p i = 1)
    (hA  : ∀ i, A i = 1 ∨ A i = -1) (hA' : ∀ i, A' i = 1 ∨ A' i = -1)
    (hB  : ∀ i, B i = 1 ∨ B i = -1) (hB' : ∀ i, B' i = 1 ∨ B' i = -1) :
    |∑ i, p i * chsh (A i) (A' i) (B i) (B' i)| ≤ 2 := by
  have hbound : ∀ i, |chsh (A i) (A' i) (B i) (B' i)| ≤ 2 :=
    fun i => chsh_abs_pointwise (A i) (A' i) (B i) (B' i) (hA i) (hA' i) (hB i) (hB' i)
  rw [abs_le]
  refine ⟨?_, ?_⟩
  · -- lower bound: -2 ≤ ∑ p i * chsh_i
    have hstep : ∀ i ∈ Finset.univ, p i * (-2) ≤ p i * chsh (A i) (A' i) (B i) (B' i) := by
      intro i _
      exact mul_le_mul_of_nonneg_left (abs_le.mp (hbound i)).1 (hp0 i)
    calc (-2 : ℝ) = (∑ i, p i) * (-2) := by rw [hp1]; ring
      _ = ∑ i, p i * (-2) := by rw [Finset.sum_mul]
      _ ≤ ∑ i, p i * chsh (A i) (A' i) (B i) (B' i) := Finset.sum_le_sum hstep
  · -- upper bound: ∑ p i * chsh_i ≤ 2
    have hstep : ∀ i ∈ Finset.univ, p i * chsh (A i) (A' i) (B i) (B' i) ≤ p i * 2 := by
      intro i _
      exact mul_le_mul_of_nonneg_left (abs_le.mp (hbound i)).2 (hp0 i)
    calc ∑ i, p i * chsh (A i) (A' i) (B i) (B' i)
          ≤ ∑ i, p i * 2 := Finset.sum_le_sum hstep
      _ = (∑ i, p i) * 2 := by rw [Finset.sum_mul]
      _ = 2 := by rw [hp1]; ring

end QHProofs.CHSH

"""The AgentDojo widening pair count comes from a power calculation, not convenience.

Pins ``power_sample_size`` (a pure two-proportion helper, no agentdojo / API key needed) so the
number documented in ``benchmarks/agentdojo/RESULTS.md`` "Widening plan" stays tied to the code.
"""

from __future__ import annotations

import pytest
from benchmarks.agentdojo.run import power_sample_size


class TestPowerSampleSize:
    def test_documented_widening_target(self) -> None:
        # 45% -> 30% (a conservative 15pp reduction), two-sided alpha=0.05, 80% power.
        # This is the number written into RESULTS.md as the per-arm pair target.
        assert power_sample_size(0.45, 0.30) == 163

    def test_larger_effect_needs_fewer_pairs(self) -> None:
        assert power_sample_size(0.45, 0.25) < power_sample_size(0.45, 0.30)

    def test_higher_power_needs_more_pairs(self) -> None:
        assert power_sample_size(0.45, 0.30, power=0.90) > power_sample_size(0.45, 0.30, power=0.80)

    def test_symmetric_in_direction(self) -> None:
        # Detecting a rise or a fall of the same magnitude needs the same n.
        assert power_sample_size(0.30, 0.45) == power_sample_size(0.45, 0.30)

    @pytest.mark.parametrize("p1,p2", [(0.0, 0.3), (0.5, 1.0), (0.4, 0.4), (-0.1, 0.2)])
    def test_rejects_degenerate_inputs(self, p1: float, p2: float) -> None:
        with pytest.raises(ValueError):
            power_sample_size(p1, p2)

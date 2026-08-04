"""Guard: the OpenAI Guardrails base classes are abstract.

``InputGuardrail`` / ``OutputGuardrail`` previously defined ``check`` as a
plain method that raised ``NotImplementedError`` — so a subclass that forgot
to override it (or the base itself) was instantiable and only failed at call
time, deep inside a request. Making them ``abc.ABC`` with ``@abstractmethod``
moves that failure to construction. This test locks the contract.
"""

from __future__ import annotations

import abc

import pytest

from agent_airlock.integrations.openai_guardrails import (
    GuardrailResult,
    InputGuardrail,
    OutputGuardrail,
    PIIGuardrail,
)


class TestGuardrailBasesAreAbstract:
    def test_bases_are_abc(self) -> None:
        assert issubclass(InputGuardrail, abc.ABC)
        assert issubclass(OutputGuardrail, abc.ABC)

    def test_input_base_cannot_be_instantiated(self) -> None:
        with pytest.raises(TypeError, match="abstract"):
            InputGuardrail()  # type: ignore[abstract]

    def test_output_base_cannot_be_instantiated(self) -> None:
        with pytest.raises(TypeError, match="abstract"):
            OutputGuardrail()  # type: ignore[abstract]

    def test_subclass_missing_override_fails_at_construction(self) -> None:
        class Incomplete(InputGuardrail):
            pass

        with pytest.raises(TypeError, match="abstract"):
            Incomplete()  # type: ignore[abstract]

    def test_subclass_with_override_constructs(self) -> None:
        class Complete(OutputGuardrail):
            def check(self, output_data: object) -> GuardrailResult:
                return GuardrailResult(passed=True)

        assert Complete().check("anything").passed is True

    def test_shipped_subclass_still_constructs(self) -> None:
        # PIIGuardrail overrides check, so the abstractness change must not
        # regress the real subclass users rely on.
        assert PIIGuardrail().check("no pii here").passed is True

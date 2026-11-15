-- D1: injected-instruction signature in any tool output. Single layer.
-- Detects attempts, not compromise. OWASP LLM01; ATLAS AML.T0051.001.
SELECT session_id, step_order, 'signature in output of ' || tool_name AS evidence
FROM injection_signature_hits;

-- D2: an action call follows a signature hit in the same session (step order).
-- Cross-step. OWASP LLM01 + LLM06 Excessive Agency.
SELECT DISTINCT a.session_id, a.step_order,
       a.tool_name || ' after signature at step ' || h.step_order AS evidence
FROM action_calls a
JOIN injection_signature_hits h
  ON h.session_id = a.session_id AND h.step_order < a.step_order;

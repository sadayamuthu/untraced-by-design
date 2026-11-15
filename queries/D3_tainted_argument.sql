-- D3: provenance taint, no text signature. An action argument holds an identifier
-- (email, IBAN, URL) that the user never gave but an earlier tool output contained.
-- Cross-layer: user intent (agent_trace) x tool outputs x action inputs.
-- OWASP LLM01 + LLM06; exfiltration destinations: LLM02, ATLAS AML.T0057.
SELECT DISTINCT i.session_id, i.step_order,
       i.tool_name || ' uses ' || i.ident || ' from output of ' || src.tool_name AS evidence
FROM action_identifiers i
JOIN user_task u USING (session_id)
JOIN agent_tool_calls src
  ON src.session_id = i.session_id
 AND src.step_order < i.step_order
 AND contains(lower(src.tool_output), i.ident)
WHERE NOT contains(u.task, i.ident);

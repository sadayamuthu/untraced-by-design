-- D5: D3 restricted to identifiers that came from an output matching the D1 signature.
-- Highest-precision provenance chain: injected text -> identifier -> action.
SELECT DISTINCT i.session_id, i.step_order,
       i.tool_name || ' uses ' || i.ident || ' from injected output at step ' || h.step_order AS evidence
FROM action_identifiers i
JOIN user_task u USING (session_id)
JOIN agent_tool_calls src
  ON src.session_id = i.session_id AND src.step_order < i.step_order
 AND contains(lower(src.tool_output), i.ident)
JOIN injection_signature_hits h
  ON h.session_id = src.session_id AND h.step_order = src.step_order
WHERE NOT contains(u.task, i.ident);

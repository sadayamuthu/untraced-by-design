-- B0 baseline: the classic phrase only. Single layer (tool output).
-- OWASP LLM01 Prompt Injection; ATLAS AML.T0051.001 (indirect).
SELECT session_id, step_order, 'ignore-previous phrase in ' || tool_name AS evidence
FROM agent_tool_calls
WHERE regexp_matches(tool_output, 'ignore\s+(all\s+)?previous\s+instructions', 'i');

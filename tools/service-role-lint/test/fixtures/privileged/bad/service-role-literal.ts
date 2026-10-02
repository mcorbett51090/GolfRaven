// MUST-FAIL (privileged-forbidden-role): a bare `service_role` string anywhere (here a membership check that would ACCEPT the BYPASSRLS role).
export const ACCEPTABLE_ROLES = ["edge_gateway", "service_role"];

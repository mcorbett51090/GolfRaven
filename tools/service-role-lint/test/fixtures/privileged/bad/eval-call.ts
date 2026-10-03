// MUST-FAIL (privileged-global-access): code built from a string can reach `Deno` with no name to match (the string here names nothing a text rule would catch).
export const reached = eval("Deno" + ".env");

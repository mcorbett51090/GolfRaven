// MUST-FAIL (privileged-global-access): dynamic import() loads code (a data: URL, another driver) this pass never sees.
export const loaded = import("data:text/javascript,export default 1");

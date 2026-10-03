// MUST-FAIL (privileged-unsafe-sql): postgres.js `sql.file(path)` runs a file read at run time as SQL: a raw-SQL entry point outside every SQL-text rule.
export const q = (t: any) => t.file("/etc/passwd");

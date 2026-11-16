export function runUserQuery(pool, targetName) {
  return pool.query("SELECT * FROM accounts WHERE owner = '" + targetName + "'");
}

export function runCommandHelper(childProc, rawArg) {
  return childProc.exec("ls -la " + rawArg);
}

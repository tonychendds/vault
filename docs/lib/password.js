const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digit: "0123456789",
  symbol: "!@#$%^&*()-_=+[]{}?",
};

function randomIndex(max) {
  if (max <= 0 || max > 256) throw new Error("Character set is empty.");
  const limit = Math.floor(256 / max) * max;
  const buffer = new Uint8Array(1);
  let value = 0;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % max;
}

export function generatePassword(length, options) {
  const sets = [];
  if (options.lower) sets.push(SETS.lower);
  if (options.upper) sets.push(SETS.upper);
  if (options.digit) sets.push(SETS.digit);
  if (options.symbol) sets.push(SETS.symbol);
  if (!sets.length) throw new Error("Choose at least one character set.");
  if (!Number.isInteger(length) || length < sets.length || length > 128) {
    throw new Error("Password length is out of range.");
  }
  const alphabet = sets.join("");
  const chars = sets.map((set) => set[randomIndex(set.length)]);
  while (chars.length < length) chars.push(alphabet[randomIndex(alphabet.length)]);
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swap = randomIndex(index + 1);
    const hold = chars[index];
    chars[index] = chars[swap];
    chars[swap] = hold;
  }
  return chars.join("");
}

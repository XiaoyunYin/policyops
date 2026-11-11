// Client-side mirror of the server's message text rules (policyops_contracts.scalars.MessageText): 1 to 4000 Unicode
// code points, well-formed (no unpaired surrogate, which cannot be encoded as UTF-8), and no control character other
// than tab and line feed (so no carriage return and nothing in U+007F..U+009F). The server stays authoritative; this
// only explains a refusal before sending. The check is bounded: input longer than twice the limit in UTF-16 units is
// too long without being scanned.

export const MAX_MESSAGE_CODE_POINTS = 4000;
const MAX_UNITS = 2 * MAX_MESSAGE_CODE_POINTS;

export type TextProblem = "empty" | "tooLong" | "control" | "surrogate";

export interface TextCheck {
  /** Code points counted, or null when the input was too long to count. */
  readonly codePoints: number | null;
  readonly problem: TextProblem | null;
}

export function checkMessageText(text: string): TextCheck {
  if (text.length === 0) {
    return { codePoints: 0, problem: "empty" };
  }
  if (text.length > MAX_UNITS) {
    return { codePoints: null, problem: "tooLong" };
  }
  let codePoints = 0;
  let problem: TextProblem | null = null;
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = index + 1 < text.length ? text.charCodeAt(index + 1) : 0;
      if (low >= 0xdc00 && low <= 0xdfff) {
        index += 1;
      } else {
        problem ??= "surrogate";
      }
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      problem ??= "surrogate";
    } else if ((unit < 0x20 && unit !== 0x09 && unit !== 0x0a) || (unit >= 0x7f && unit < 0xa0)) {
      problem ??= "control";
    }
    codePoints += 1;
  }
  if (problem === null && codePoints > MAX_MESSAGE_CODE_POINTS) {
    problem = "tooLong";
  }
  return { codePoints, problem };
}

export const TEXT_PROBLEMS: Readonly<Record<TextProblem, string>> = {
  empty: "Enter a message.",
  tooLong: `A message can be at most ${MAX_MESSAGE_CODE_POINTS.toLocaleString("en-US")} characters.`,
  control: "Remove control characters. Only tabs and line breaks are allowed.",
  surrogate: "The text contains an incomplete character. Remove it, then try again.",
};

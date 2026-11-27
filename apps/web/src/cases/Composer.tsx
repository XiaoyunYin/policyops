// Composer for staff: an internal staff note, or a customer message the operator types in as a simulation. The
// message type has no default, a customer message needs an explicit confirmation, and the model-simulated customer is
// shown as unavailable (it sends nothing). Nothing here is customer consent. Escape or "Back to editing" leaves the
// confirmation and returns focus to the message field, as does a successful post (`focusSignal`).

import { useEffect, useId, useRef, useState } from "react";
import { Button } from "react-aria-components/Button";
import { Label, RadioButton, RadioField, RadioGroup } from "react-aria-components/RadioGroup";
import { Text } from "react-aria-components/Text";
import { TextArea } from "react-aria-components/TextArea";
import { TextField } from "react-aria-components/TextField";

import type { Draft } from "./CaseDetail";
import { MAX_MESSAGE_CODE_POINTS, TEXT_PROBLEMS, checkMessageText } from "./text";

const UNAVAILABLE = "simulated_customer";

export function Composer({ draft, locked, submitDisabled, focusSignal, onChange, onSend }: {
  draft: Draft;
  /** A message from this view is being sent or has an unconfirmed outcome: nothing can be edited or sent. */
  locked: boolean;
  /** A case version refresh is in progress. The operator can still edit the draft. */
  submitDisabled: boolean;
  /** Changes when focus should return to the message field (after a successful post). */
  focusSignal: number;
  onChange: (draft: Draft) => void;
  onSend: () => void;
}) {
  const [attempted, setAttempted] = useState(false);
  const confirmId = useId();
  const textRef = useRef<HTMLTextAreaElement>(null);
  const check = checkMessageText(draft.text);
  const count = check.codePoints === null ? `More than ${MAX_MESSAGE_CODE_POINTS.toLocaleString("en-US")}`
    : check.codePoints.toLocaleString("en-US");
  const problem = attempted && check.problem !== null ? TEXT_PROBLEMS[check.problem] : null;
  const sourceMissing = attempted && draft.source === null;

  useEffect(() => {
    if (focusSignal > 0) {
      textRef.current?.focus();
    }
  }, [focusSignal]);

  const backToEditing = (): void => {
    onChange({ ...draft, confirming: false });
    textRef.current?.focus();
  };

  const submit = (): void => {
    if (submitDisabled) return;
    setAttempted(true);
    if (locked || draft.source === null || check.problem !== null) {
      return;
    }
    if (draft.source === "operator_entered_customer" && !draft.confirming) {
      onChange({ ...draft, confirming: true });
      return;
    }
    setAttempted(false);
    onSend();
  };

  return (
    <form className="composer" onSubmit={(event) => {
      event.preventDefault();
      submit();
    }}>
      <RadioGroup className="source-group" value={draft.source} isDisabled={locked || draft.confirming}
                  isInvalid={sourceMissing} onChange={(value) => {
                    if (value === "staff_note" || value === "operator_entered_customer") {
                      onChange({ ...draft, source: value, confirming: false });
                    }
                  }}>
        <Label>Message type</Label>
        <RadioField value="staff_note">
          <RadioButton className="source-choice">Staff note</RadioButton>
          <Text slot="description" className="muted choice-help">Internal. Never sent to the customer.</Text>
        </RadioField>
        <RadioField value="operator_entered_customer">
          <RadioButton className="source-choice">Customer message, entered by me</RadioButton>
          <Text slot="description" className="muted choice-help">A simulation: you type what the customer said.
            Staff-entered demo customer reply; the server checks whether it confirms the presented action.</Text>
        </RadioField>
        <RadioField value={UNAVAILABLE} isDisabled>
          <RadioButton className="source-choice">Simulated customer (model)</RadioButton>
          <Text slot="description" className="muted choice-help">Unavailable: no model-simulated customer is
            connected.</Text>
        </RadioField>
        {sourceMissing ? <Text slot="errorMessage" className="field-error">Choose a message type.</Text> : null}
      </RadioGroup>
      <TextField className="text-field" value={draft.text} isReadOnly={locked || draft.confirming}
                 isInvalid={problem !== null} onChange={(text) => {
                   onChange({ ...draft, text, confirming: false });
                 }}>
        <Label>Message</Label>
        <TextArea className="textarea" rows={4} ref={textRef} />
        <Text slot="description" className="muted">{count} / {MAX_MESSAGE_CODE_POINTS.toLocaleString("en-US")}
          {" "}characters</Text>
        {problem !== null ? <Text slot="errorMessage" className="field-error">{problem}</Text> : null}
      </TextField>
      {draft.confirming ? (
        <div className="confirm" role="group" aria-labelledby={confirmId} onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.preventDefault();
            backToEditing();
          }
        }}>
          <p id={confirmId}>Post this as a <strong>customer message entered by you</strong>? It's labeled as a
            staff-entered simulation. The server checks whether it confirms the presented action; posting alone does not establish consent.</p>
          <div className="actions">
            <Button className="button button-primary" type="submit" isDisabled={locked || submitDisabled}
                    autoFocus>Confirm post</Button>
            <Button className="button" onPress={backToEditing}>Back to editing</Button>
          </div>
        </div>
      ) : (
        <Button className="button button-primary" type="submit" isDisabled={locked || submitDisabled}>
          {draft.source === "operator_entered_customer" ? "Post customer message…" : "Post"}
        </Button>
      )}
    </form>
  );
}

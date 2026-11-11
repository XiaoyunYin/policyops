// Shared status, empty and error presentation. All server text is rendered as plain text nodes.

import { useEffect, useId, type ReactNode } from "react";
import { Button } from "react-aria-components/Button";

import type { ApiError } from "../api/client";

export function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} · PolicyOps`;
  }, [title]);
}

export function Status({ label }: { label: string }) {
  return (
    <div className="status" role="status">
      <span className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

export interface ErrorCopy {
  title: string;
  body: string;
}

export function describeError(error: ApiError): ErrorCopy {
  switch (error.kind) {
    case "network":
      return { title: "Can't reach PolicyOps", body: "Check your connection, then try again." };
    case "timeout":
      return { title: "The server didn't respond in time", body: "Try again in a moment." };
    case "malformed":
      return { title: "Unexpected response", body: "The server sent a response this page couldn't read." };
    case "cancelled":
      return { title: "Request cancelled", body: "The request was cancelled before it finished." };
    case "http":
      break;
  }
  const status = error.status ?? 0;
  if (status === 403) {
    return { title: "You don't have access", body: error.detail ?? "Your roles in this workspace don't allow this." };
  }
  if (status === 404) {
    // Hidden and missing resources read the same.
    return { title: "Not found", body: "It doesn't exist, or it isn't available in this workspace." };
  }
  if (status === 429) {
    return { title: "Too many requests", body: "Wait a moment, then try again." };
  }
  if (status === 503) {
    return { title: "Service unavailable", body: "A required service is unavailable. Try again shortly." };
  }
  if (status >= 500) {
    return { title: "Something went wrong", body: "The server couldn't complete the request." };
  }
  return { title: "Request not completed", body: error.detail ?? "The server refused the request." };
}

/** Reads may be retried after transport failures, server failures, or when the server says so. */
export function canRetry(error: ApiError): boolean {
  if (error.kind !== "http") {
    return error.kind !== "cancelled";
  }
  return error.code === null ? (error.status ?? 0) >= 500 : error.retryable;
}

export function Reference({ id }: { id: string | null }) {
  if (id === null) {
    return null;
  }
  return (
    <p className="reference">
      Reference <code className="reference-id">{id}</code>
    </p>
  );
}

export function ErrorPanel({ error, onRetry, retryLabel = "Try again" }: {
  error: ApiError;
  onRetry?: () => void;
  retryLabel?: string;
}) {
  const copy = describeError(error);
  const titleId = useId();
  return (
    <section className="panel panel-error" role="alert" aria-labelledby={titleId}>
      <h2 id={titleId}>{copy.title}</h2>
      <p>{copy.body}</p>
      <Reference id={error.correlationId} />
      {onRetry !== undefined && canRetry(error) ? (
        <Button className="button" onPress={onRetry}>{retryLabel}</Button>
      ) : null}
    </section>
  );
}

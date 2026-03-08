export interface HookEvent {
  type: "command" | "message" | "lifecycle";
  action: string;
  sessionId?: string;
  messages: string[];
  [key: string]: unknown;
}

export type HookHandler = (event: HookEvent) => Promise<void>;

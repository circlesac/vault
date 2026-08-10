export type MutationTarget = {
  account: string
  host: string
}

export function mutationTarget(config: { baseUrl: string; org: string | null }): MutationTarget {
  return {
    account: config.org ? `org:${config.org}` : "personal",
    host: new URL(config.baseUrl).origin,
  }
}

export function mutationResult<T extends object>(
  value: T,
  target: MutationTarget
): T & MutationTarget {
  return { ...value, ...target }
}

export function mutationTargetLine(target: MutationTarget): string {
  return `Account: ${target.account} @ ${target.host}`
}

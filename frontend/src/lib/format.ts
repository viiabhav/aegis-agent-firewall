export const pretty = (value: string) => value.replaceAll('_', ' ').replace(/\b\w/g, (m) => m.toUpperCase())

export const pct = (value: number) => `${Math.round(value * 100)}%`

export const compactTime = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

// One source behind an answer, as `logbook cites --json` prints it.
export type Source = {
  n: number
  mark: string
  id: string
  header: string // the note's own title
  commit_header: string // the commit or pull request it sits under, '' when it has none
  url: string
  author: string
  date: string
  scope: 'private' | 'shared'
  mine: boolean
  has_commit: boolean
  expandable: boolean
  detail: string
}

declare module 'claude-code' {
  interface PluginState {
    logbook: {
      shown: Source[] // every source cited so far in this chat, in number order
      find: { text: string; at: number } // the finder: what was typed, and which instance it is on (from 0)
      open: boolean // the band is expanded
      owner: string // the session id the list was built in; a different id means a new chat
    }
  }
}

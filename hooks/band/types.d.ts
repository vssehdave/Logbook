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
      shown: Source[] // the sources cited in the latest answer
      seen: string[] // note ids cited anywhere in this chat
      open: boolean // the band is expanded
    }
  }
}

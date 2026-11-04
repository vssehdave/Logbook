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

// An answer that cites a number, as `logbook cites --where` prints it: the transcript row's id (what the engine scrolls to) and the words
// before and after the citation (the peek).
export type Hit = { uuid: string; before: string; after: string }

declare module 'claude-code' {
  interface PluginState {
    logbook: {
      shown: Source[] // every source cited so far in this chat, in number order
      find: { text: string; at: number } // the finder: the number clicked, and which answer's peek is showing (from 0, oldest first)
      peek: Hit[] // the answers that cite the clicked number, oldest first
      open: boolean // the band is expanded
      mode: string // the publish mode: never, ask, claude or auto
      owner: string // the session id the list was built in; a different id means a new chat
    }
  }
}

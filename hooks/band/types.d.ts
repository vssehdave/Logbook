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

// An answer that cites a number: the words before and after the citation (the peek), and `core`, a short stretch ending at the citation that
// finds the same message among those the engine has drawn.
export type Hit = { before: string; after: string; core: string }

// A message block the engine drew that cites something.
export type Drawn = { id: string; text: string }

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

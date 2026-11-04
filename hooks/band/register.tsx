import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { Source } from './types'

// The Sources band: above the prompt, every numbered note cited so far in this chat (it stays until /clear, and grows as answers cite
// more). Compact it is one line of titles; expanded it adds, for a note a teammate shared, the commit or pull request header and link,
// who wrote it and when. Your own and private notes stay one line.
const shown = atom({ plugin: 'logbook', key: 'shown' } as const, [] as Source[])
const open = atom({ plugin: 'logbook', key: 'open' } as const, false)

const SUPERSCRIPT = '⁰¹²³⁴⁵⁶⁷⁸⁹'
const RUNNERS: readonly (readonly string[])[] = [['logbook'], ['python', '-m', 'getlogbook'], ['python3', '-m', 'getlogbook']]

// Numbers written as superscripts in an answer: "…rounds half-even¹ and the export drops refunds²" -> [1, 2].
export const citedNumbers = (answer: string): number[] => {
  const found = new Set<number>()
  for (const run of answer.match(/[⁰¹²³⁴⁵⁶⁷⁸⁹]+/g) ?? []) {
    found.add(Number([...run].map(ch => SUPERSCRIPT.indexOf(ch)).join('')))
  }
  return [...found]
}

// The chat's bibliography after an answer cited `fresh`: what was there stays, new sources are added, a source is refreshed, in number order.
export const mergeSources = (was: readonly Source[], fresh: readonly Source[]): Source[] => {
  const byId = new Map(was.map(s => [s.id, s] as const))
  for (const s of fresh) byId.set(s.id, s)
  return [...byId.values()].sort((a, b) => a.n - b.n)
}

// What Copy puts on the clipboard: the full bibliography, whichever view is open.
export const bibliography = (sources: readonly Source[]): string =>
  sources.map(s => `${s.mark} ${s.expandable ? s.detail : s.header}`).join('\n')

const short = (text: string, max = 48): string => (text.length > max ? `${text.slice(0, max - 1)}…` : text)

let runner: readonly string[] | undefined

// The numbered sources of this chat, from the logbook command; [] when it is missing or this is not a Logbook repo.
async function sourcesOf($: EngineInterface, session: string): Promise<Source[]> {
  for (const argv of runner ? [runner] : RUNNERS) {
    try {
      const done = await $.process.run([...argv, 'cites', '--json', '--session', session], { timeoutMs: 8000 })
      if (done.exitCode === 0) {
        runner = argv
        return JSON.parse(done.stdout).sources as Source[]
      }
    } catch {
      // that spelling of the command is not installed: try the next
    }
  }
  return []
}

export const register: Register = on => {
  on('turn.complete', async ($, e, next) => {
    if (!e.agentId && e.reason === 'answer') {
      const marks = citedNumbers(e.answer)
      // An answer that cites nothing leaves the band as it was; the sources are the chat's, not the last answer's.
      if (marks.length) {
        const fresh = (await sourcesOf($, await $.session.id())).filter(s => marks.includes(s.n))
        await update($, shown, was => mergeSources(was, fresh))
      }
    }
    return next(e)
  })

  // /clear starts a new chat, and numbering starts again at one with it.
  on('session.end', async ($, e, next) => {
    if (e.reason === 'clear') {
      await update($, shown, () => [])
    }
    return next(e)
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const sources = await read($, shown)
    if (e.props.hasSurvey || sources.length === 0) return next(e)
    // Other mods share this slot: draw theirs below ours instead of replacing it.
    const below = await next(e).catch(() => undefined)
    const isOpen = await read($, open)
    const { Box, Button, Text } = $.ui.resolve(e)
    const width = e.surface === 'terminal' ? e.props.bodyColumns : undefined

    const toggle = () => update($, open, was => !was)
    const copy = async () => {
      const done = await $.ui.copy({ text: bibliography(sources), surface: e.surface })
      $.ui.toast(done.isCopied ? 'Sources copied' : `Copy failed: ${done.reason}`)
    }

    const head = (
      <Box flexDirection="row" alignItems="center" gap={2} width={width}>
        <Text dimColor>Sources</Text>
        {isOpen ? (
          <Text dimColor>{sources.length} cited in this chat</Text>
        ) : (
          <Text wrap="truncate-end">{sources.map(s => `${s.mark} ${short(s.header)}`).join(' · ')}</Text>
        )}
        <Box flexGrow={1} />
        <Button key="copy" plain label="Copy" onPress={copy} />
        <Button key="toggle" plain label={isOpen ? 'collapse [-]' : 'expand [+]'} onPress={toggle} />
      </Box>
    )

    const body = isOpen ? (
      <Box flexDirection="column" width={width}>
        {sources.map(s => (
          <Box key={s.id} flexDirection="column">
            <Text>
              {s.mark} {s.header}
              {s.expandable && s.has_commit ? <Text dimColor>{`  ${s.commit_header}  ·  ${s.author}, ${s.date}`}</Text> : null}
            </Text>
            {s.expandable && s.has_commit && s.url !== '' ? <Text dimColor>{`  ${s.url}`}</Text> : null}
            {s.expandable && !s.has_commit ? <Text dimColor>{`  Note added by ${s.author} on ${s.date}`}</Text> : null}
          </Box>
        ))}
      </Box>
    ) : null

    const mine = (
      <Box flexDirection="column">
        {head}
        {body}
      </Box>
    )
    return below ? (
      <Box flexDirection="column">
        {mine}
        {below}
      </Box>
    ) : (
      mine
    )
  })
}

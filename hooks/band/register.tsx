import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { Source } from './types'

// The bibliography band, above the prompt. It is always there: a title, how many sources this chat has cited, and a finder that shows
// which citation you clicked and steps (x/y) through the answers that cite it. Under it, the sources cited so far, kept until /clear.
// Compact they are `¹ title` buttons that fit the width; with details on, each teammate-shared note also shows its commit or pull request
// header as a link, who wrote it and when. Clicking a citation scrolls the chat to the first answer that cites it.
const shown = atom({ plugin: 'logbook', key: 'shown' } as const, [] as Source[])
const find = atom({ plugin: 'logbook', key: 'find' } as const, { text: '', at: 0 })
const open = atom({ plugin: 'logbook', key: 'open' } as const, false)
const owner = atom({ plugin: 'logbook', key: 'owner' } as const, '') // the session id the list was built in

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

// Which chat messages cite which number, in the order they were first drawn. One message counts once however often it cites.
export const addInstances = (was: Record<string, string[]>, marks: readonly number[], requestId: string): Record<string, string[]> => {
  let next = was
  for (const n of marks) {
    const ids = was[String(n)] ?? []
    if (!ids.includes(requestId)) next = { ...next, [String(n)]: [...ids, requestId] }
  }
  return next
}

// "2", "[2]" and "²" all mean citation 2; anything without a digit means none.
export const queryNumber = (text: string): number | undefined => {
  const digits = queryDigits(text)
  return digits === '' ? undefined : Number(digits)
}

// What the finder keeps of what was typed: the digits only (a superscript counts as its digit), at most three. A chat will not cite a
// thousand sources, and the field has room for three.
export const queryDigits = (text: string): string =>
  [...text]
    .map(ch => (SUPERSCRIPT.includes(ch) ? String(SUPERSCRIPT.indexOf(ch)) : /[0-9]/.test(ch) ? ch : ''))
    .join('')
    .slice(0, 3)

// The next or previous instance, going round at the ends.
export const stepInstance = (at: number, total: number, by: 1 | -1): number => (total === 0 ? 0 : (at + by + total) % total)

const short = (text: string, max = 28): string => (text.length > max ? `${text.slice(0, max - 1)}…` : text)

// How many `[n] title` items fit one row of `columns` cells (each takes its title, the number, a gap), and how many are left over.
export const fitCompact = (sources: readonly Source[], columns: number): { fits: Source[]; more: number } => {
  const room = Math.max(10, columns - 34) // the finder and the toggle live in the row above
  let used = 0
  const fits: Source[] = []
  for (const s of sources) {
    const cost = short(s.header).length + String(s.n).length + 5
    if (used + cost > room && fits.length > 0) break
    used += cost
    fits.push(s)
  }
  return { fits, more: sources.length - fits.length }
}

// A number as superscript digits (12 -> ¹²): the label the band and the answers use.
export const sup = (n: number): string => [...String(n)].map(d => SUPERSCRIPT[Number(d)]).join('')
export const label = (n: number): string => sup(n)

let runner: readonly string[] | undefined
// Which chat messages cite which number. Kept here and not in $.state: the engine refuses state writes while a message is drawn, and noting
// a message as it is drawn is the only way to learn its id. The band reads it when it is drawn, which is after the answer has been.
let instances: Record<string, string[]> = {}

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

// How each system opens an address; the first that starts is used. No shell: the address is one argument.
const OPENERS: readonly (readonly string[])[] = [['rundll32', 'url.dll,FileProtocolHandler'], ['open'], ['xdg-open']]

// Opens a page in the browser. The commit header in the list is a button that does this and not a Link: a Link is a terminal hyperlink,
// and where the terminal does not support those the engine draws the address beside the text instead of on it. https only.
async function openUrl($: EngineInterface, url: string): Promise<void> {
  if (!/^https:\/\//.test(url)) {
    $.ui.toast('Not opening an address that is not https')
    return
  }
  for (const argv of OPENERS) {
    try {
      await $.process.run([...argv, url], { timeoutMs: 5000 })
      return
    } catch {
      // not this system's opener: try the next
    }
  }
  $.ui.toast('Could not open the link')
}

// Scrolls the chat to one answer. The engine allows it only while answering the person's own click or typing, which is when this runs.
async function goTo($: EngineInterface, requestId: string): Promise<void> {
  const done = await $.ui.scroll({ to: { requestId }, block: 'center' })
  if (done.deny) $.ui.toast(`Could not scroll there: ${done.deny}`)
}

export const register: Register = on => {
  on('turn.complete', async ($, e, next) => {
    if (!e.agentId && e.reason === 'answer') {
      const session = await $.session.id()
      // A different session id means a new chat (/clear, resume): nothing of the old one may stay.
      if ((await read($, owner)) !== session) {
        instances = {}
        await update($, shown, () => [])
        await update($, find, () => ({ text: '', at: 0 }))
        await update($, owner, () => session)
      }
      const marks = citedNumbers(e.answer)
      // An answer that cites nothing leaves the band as it was; the sources are the chat's, not the last answer's.
      if (marks.length) {
        const all = await sourcesOf($, session)
        // The cited ones are added, and the ones already listed are refreshed (a link or a name may have been added since).
        await update($, shown, was => mergeSources(was, all.filter(s => marks.includes(s.n) || was.some(w => w.id === s.id))))
      }
    }
    return next(e)
  })

  // Note which messages cite which number, as they are drawn, so the finder can walk them.
  on('ui.render', { component: 'AssistantMessage' }, async ($, e, next) => {
    const marks = citedNumbers(e.props.text)
    if (marks.length) instances = addInstances(instances, marks, e.requestId)
    return next(e)
  })

  // /clear starts a new chat, and numbering starts again at one with it.
  on('session.end', async ($, e, next) => {
    if (e.reason === 'clear') {
      await update($, shown, () => [])
      instances = {}
      await update($, find, () => ({ text: '', at: 0 }))
    }
    return next(e)
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    // Other mods share this slot: draw theirs below ours instead of replacing it.
    const below = await next(e).catch(() => undefined)
    // The list belongs to the session it was built in; after /clear the id differs and the band is empty at once. No owner yet (just
    // loaded, no answer has completed since) is not a different chat: show what is kept.
    const owned = await read($, owner)
    const sources = owned === '' || owned === (await $.session.id()) ? await read($, shown) : []
    const isOpen = await read($, open)
    const seen = instances
    const query = await read($, find)
    const wanted = queryNumber(query.text)
    const ids = wanted === undefined ? [] : (seen[String(wanted)] ?? [])
    const at = ids.length ? Math.min(query.at, ids.length - 1) : 0
    const { Box, Button, Text } = $.ui.resolve(e)
    const width = e.surface === 'terminal' ? e.props.bodyColumns : undefined

    const toggle = () => update($, open, was => !was)
    const move = async (by: 1 | -1) => {
      if (ids.length === 0) return
      const to = stepInstance(at, ids.length, by)
      await update($, find, was => ({ ...was, at: to }))
      await goTo($, ids[to] as string)
    }
    // A click on a citation in the list: make it the finder's number and go to the first answer that cites it.
    const pick = async (n: number) => {
      const found = seen[String(n)] ?? []
      await update($, find, () => ({ text: String(n), at: 0 }))
      if (found.length) await goTo($, found[0] as string)
      else $.ui.toast(`${label(n)} has no answer on screen yet`)
    }
    const head = (
      <Box flexDirection="row" alignItems="center" gap={2} width={width}>
        <Text>bibliography</Text>
        <Text dimColor>{sources.length} cited in this chat</Text>
        <Box flexGrow={1} />
        {/* The finder: arrows, the number of the citation clicked in the list (dim "n" until one is), and x/y. Nothing can be typed:
            a text field makes the engine draw an enter hint and its width cannot be controlled. The number is the one the list set. */}
        <Box flexDirection="row" alignItems="center" gap={1}>
          <Button key="prev" plain label="↑" onPress={() => move(-1)} />
          <Button key="next" plain label="↓" onPress={() => move(1)} />
          <Box flexDirection="row">
            <Text dimColor>[</Text>
            {wanted === undefined ? <Text dimColor>n</Text> : <Text>{wanted}</Text>}
            <Text dimColor>]</Text>
          </Box>
          <Text dimColor>
            {ids.length ? at + 1 : 0}/{ids.length}
          </Text>
        </Box>
        <Button key="toggle" plain label="details" onPress={toggle} />
      </Box>
    )

    const fit = fitCompact(sources, width ?? 80)
    const compact =
      sources.length === 0 ? null : (
        <Box flexDirection="row" gap={2} width={width}>
          {fit.fits.map(s => (
            <Box key={s.id} flexDirection="row" gap={1}>
              <Button key={`src:${s.n}`} plain label={label(s.n)} onPress={() => pick(s.n)} />
              <Text>{short(s.header)}</Text>
            </Box>
          ))}
          {fit.more > 0 ? <Text dimColor>+{fit.more} more</Text> : null}
        </Box>
      )

    // Taller than the band may be, the engine scrolls it (the wheel, or the keys while the band is focused) and says how many rows are hidden.
    const list = (
      <Box flexDirection="column" width={width}>
        {sources.map(s => (
          <Box key={s.id} flexDirection="row" gap={1}>
            <Button key={`src:${s.n}`} plain label={label(s.n)} onPress={() => pick(s.n)} />
            <Text>{s.header}</Text>
            {s.expandable ? <Text dimColor>·</Text> : null}
            {s.expandable && s.has_commit && s.url !== '' ? (
              <Button key={`url:${s.n}`} plain onPress={() => openUrl($, s.url)}>
                <Text dimColor underline>
                  {s.commit_header}
                </Text>
              </Button>
            ) : null}
            {s.expandable && s.has_commit && s.url === '' ? <Text dimColor>{s.commit_header}</Text> : null}
            {s.expandable && s.has_commit ? <Text dimColor>{`· ${s.author}, ${s.date}`}</Text> : null}
            {s.expandable && !s.has_commit ? <Text dimColor>{`Note added by ${s.author} on ${s.date}`}</Text> : null}
          </Box>
        ))}
      </Box>
    )

    const mine = (
      <Box flexDirection="column">
        {head}
        {isOpen ? list : compact}
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

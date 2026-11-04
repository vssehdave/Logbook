import { describe, expect, test } from 'claude-code/testing'

import { MODES, SELECTED, citedNumbers, findDrawn, fitCompact, hitsFor, label, mergeSources, modeColor, queryDigits, queryNumber, stepInstance, sup, upsertDrawn } from '../hooks/band/register'
import type { Source } from '../hooks/band/types'

const source = (over: Partial<Source>): Source => ({
  n: 1,
  mark: '¹',
  id: 'a',
  header: 'refund rounding',
  commit_header: 'fix refund rounding',
  url: '',
  author: 'you',
  date: '',
  scope: 'private',
  mine: true,
  has_commit: true,
  expandable: false,
  detail: '',
  ...over,
})

describe('citations in an answer', () => {
  test('reads superscript numbers, including more than one digit, once each', () => {
    expect(citedNumbers('Rounds half-even¹ and drops refunds² ¹ again, see ¹¹.')).toEqual([1, 2, 11])
    expect(citedNumbers('no sources here, and 2 is not a superscript')).toEqual([])
  })
})

describe('the citation label', () => {
  test('is the number as a superscript, and reads back as the same number', () => {
    expect(sup(12)).toBe('¹²')
    expect(label(2)).toBe('²')
    expect(citedNumbers(`claim ${label(2)} and ${label(11)}`)).toEqual([2, 11])
    expect(queryNumber(label(2))).toBe(2)
  })
})

describe('the publish modes', () => {
  test('run from least to most hands-off, each with its own shade, and an unknown mode is the grey one', () => {
    expect(MODES.map(m => m.key)).toEqual(['never', 'ask', 'claude', 'auto'])
    expect(new Set(MODES.map(m => m.color)).size).toBe(4)
    expect(modeColor('auto')).not.toBe(modeColor('ask'))
    expect(modeColor('whatever')).toBe(modeColor('never'))
    expect(SELECTED).toBe(modeColor('ask'))
  })
})

describe('the chat bibliography', () => {
  test('an answer that cites more adds to it, and sources stay in number order', () => {
    const one = source({ n: 1, mark: '¹', id: 'a' })
    const two = source({ n: 2, mark: '²', id: 'b' })
    const three = source({ n: 3, mark: '³', id: 'c' })
    expect(mergeSources([], [two])).toEqual([two])
    expect(mergeSources([two], [one, three]).map(s => s.id)).toEqual(['a', 'b', 'c'])
  })

  test('a source cited again is refreshed, not listed twice, and an empty answer changes nothing', () => {
    const was = [source({ n: 1, id: 'a', header: 'old title' })]
    expect(mergeSources(was, [source({ n: 1, id: 'a', header: 'new title' })])).toEqual([source({ n: 1, id: 'a', header: 'new title' })])
    expect(mergeSources(was, [])).toEqual(was)
  })
})

describe('the finder', () => {
  test('peeks at every answer that cites a number, oldest first, with the words around the citation', () => {
    const chat = [
      { role: 'user', text: 'why is revenue wrong?' },
      { role: 'assistant', text: 'Refunds were counted as revenue² and the export is late¹.' },
      { role: 'assistant', text: 'Nothing cited here.' },
      { role: 'assistant', text: 'Again the refunds²,\n  the same finding.' },
      { role: 'assistant', text: 'A number like ²² or ¹² is another citation, not ².' },
    ]
    const hits = hitsFor(chat, 2)
    expect(hits.length).toBe(3)
    expect(hits[0]).toEqual({ before: 'Refunds were counted as revenue', after: ' and the export is late¹.', core: 'efunds were counted as revenue²' }) // the last 30 characters before the citation, and the citation
    expect(hits[1]?.after).toBe(', the same finding.')
    expect(hitsFor(chat, 22).length).toBe(1)
    expect(hitsFor(chat, 9)).toEqual([])
    expect(hitsFor(chat, 1).length).toBe(1)
  })

  test('a user message that happens to hold a superscript is not an answer', () => {
    expect(hitsFor([{ role: 'user', text: 'what is ¹?' }], 1)).toEqual([])
  })

  test('finds the drawn block of a peek, newest first, and says so when it was never drawn', () => {
    const [hit] = hitsFor([{ role: 'assistant', text: 'Refunds were counted as revenue² here.' }], 2)
    let blocks = upsertDrawn([], 'm1', 'older: Refunds were counted as revenue² here.')
    blocks = upsertDrawn(blocks, 'm2', 'newer:  Refunds were counted\nas revenue² here.')
    expect(findDrawn(blocks, (hit as { core: string }).core)).toBe('m2')
    expect(findDrawn([], (hit as { core: string }).core)).toBeUndefined()
  })

  test('a block drawn again as it streams keeps one entry with the latest text', () => {
    const blocks = upsertDrawn(upsertDrawn([], 'm1', 'Refunds¹'), 'm1', 'Refunds¹ and more')
    expect(blocks).toEqual([{ id: 'm1', text: 'Refunds¹ and more' }])
  })

  test('takes 2, [2] and the superscript as the same number, and nothing else as none', () => {
    expect(queryNumber('2')).toBe(2)
    expect(queryNumber('[2]')).toBe(2)
    expect(queryNumber('²')).toBe(2)
    expect(queryNumber('[12]')).toBe(12)
    expect(queryNumber('')).toBeUndefined()
    expect(queryNumber('abc')).toBeUndefined()
  })

  test('keeps at most the first three digits and drops everything else', () => {
    expect(queryDigits('123')).toBe('123')
    expect(queryDigits('1234')).toBe('123')
    expect(queryDigits('a1b2')).toBe('12')
    expect(queryDigits('²³')).toBe('23')
    expect(queryNumber('99999')).toBe(999)
  })

  test('steps through instances and goes round at both ends', () => {
    expect(stepInstance(0, 3, 1)).toBe(1)
    expect(stepInstance(2, 3, 1)).toBe(0)
    expect(stepInstance(0, 3, -1)).toBe(2)
    expect(stepInstance(0, 0, 1)).toBe(0)
  })
})

describe('many citations', () => {
  test('the compact row shows what fits the width and counts the rest', () => {
    const many = Array.from({ length: 12 }, (_, i) => source({ n: i + 1, id: `s${i}`, header: 'a fairly long note title here' }))
    const narrow = fitCompact(many, 80)
    expect(narrow.fits.length).toBeGreaterThan(0)
    expect(narrow.fits.length + narrow.more).toBe(12)
    expect(narrow.more).toBeGreaterThan(0)
    expect(fitCompact(many, 600).more).toBe(0)
    expect(fitCompact(many, 10).fits.length).toBe(1) // never an empty row when there are sources
  })
})

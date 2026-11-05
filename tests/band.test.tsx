import { describe, expect, test } from 'claude-code/testing'

import { MODES, SELECTED, citedNumbers, fitCompact, label, mergeSources, modeColor, queryDigits, queryNumber, stepInstance, sup } from '../hooks/band/register'
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
    expect(MODES.map(m => m.key)).toEqual(['manual', 'ask', 'auto'])
    expect(new Set(MODES.map(m => m.color)).size).toBe(3)
    expect(modeColor('auto')).not.toBe(modeColor('ask'))
    expect(modeColor('whatever')).toBe(modeColor('manual'))
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

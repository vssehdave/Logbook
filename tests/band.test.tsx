import { describe, expect, test } from 'claude-code/testing'

import { bibliography, citedNumbers } from '../hooks/band/register'
import type { Source } from '../hooks/band/types'

const source = (over: Partial<Source>): Source => ({
  n: 1,
  mark: '¹',
  id: 'a',
  header: 'fix refund rounding',
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

describe('the bibliography Copy puts on the clipboard', () => {
  test('a teammate note carries its detail; your own and private notes stay one line', () => {
    const text = bibliography([
      source({ n: 1, mark: '¹', header: 'fix refund rounding', expandable: true, scope: 'shared', mine: false, detail: 'fix refund rounding  by Priya N., 2026-10-28  https://github.com/acme/shop/pull/14' }),
      source({ n: 2, mark: '²', id: 'b', header: 'my private note' }),
    ])
    expect(text).toBe('¹ fix refund rounding  by Priya N., 2026-10-28  https://github.com/acme/shop/pull/14\n² my private note')
  })
})

// Line diff for the import preview: common prefix and suffix are trimmed,
// the middle is diffed with an LCS table. Returns hunks with context.

export function diffLines(a, b) {
  const A = a.replace(/\r\n/g, '\n').split('\n')
  const B = b.replace(/\r\n/g, '\n').split('\n')
  let pre = 0
  while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++
  let suf = 0
  while (suf < A.length - pre && suf < B.length - pre && A[A.length - 1 - suf] === B[B.length - 1 - suf]) suf++
  const a2 = A.slice(pre, A.length - suf)
  const b2 = B.slice(pre, B.length - suf)
  const n = a2.length
  const m = b2.length
  const ops = []
  for (let i = 0; i < pre; i++) ops.push({ t: ' ', s: A[i] })
  if (n * m > 16e6) {
    a2.forEach((s) => ops.push({ t: '-', s }))
    b2.forEach((s) => ops.push({ t: '+', s }))
  } else {
    // L[i][j] = LCS length of a2[i:] and b2[j:]
    const W = m + 1
    const L = new Uint32Array((n + 1) * W)
    for (let i = n - 1; i >= 0; i--)
      for (let j = m - 1; j >= 0; j--)
        L[i * W + j] = a2[i] === b2[j] ? L[(i + 1) * W + j + 1] + 1 : Math.max(L[(i + 1) * W + j], L[i * W + j + 1])
    let i = 0
    let j = 0
    while (i < n || j < m) {
      if (i < n && j < m && a2[i] === b2[j]) {
        ops.push({ t: ' ', s: a2[i++] })
        j++
      } else if (j < m && (i === n || L[i * W + j + 1] >= L[(i + 1) * W + j])) ops.push({ t: '+', s: b2[j++] })
      else ops.push({ t: '-', s: a2[i++] })
    }
  }
  for (let i = A.length - suf; i < A.length; i++) ops.push({ t: ' ', s: A[i] })
  return ops
}

// hunks collapses unchanged runs longer than 2*ctx into gaps.
export function hunks(ops, ctx = 3) {
  const keep = new Array(ops.length).fill(false)
  ops.forEach((o, i) => {
    if (o.t === ' ') return
    for (let k = Math.max(0, i - ctx); k <= Math.min(ops.length - 1, i + ctx); k++) keep[k] = true
  })
  const out = []
  let skipped = 0
  ops.forEach((o, i) => {
    if (keep[i]) {
      if (skipped) out.push({ t: '…', s: skipped })
      skipped = 0
      out.push(o)
    } else skipped++
  })
  if (skipped && out.length) out.push({ t: '…', s: skipped })
  return out
}

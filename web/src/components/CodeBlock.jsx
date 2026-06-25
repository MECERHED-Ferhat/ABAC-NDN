import { useMemo } from 'react'
import hljs from 'highlight.js/lib/core'
import cpp from 'highlight.js/lib/languages/cpp'
import bash from 'highlight.js/lib/languages/bash'
import 'highlight.js/styles/atom-one-dark.css'

hljs.registerLanguage('cpp', cpp)
hljs.registerLanguage('bash', bash)

export default function CodeBlock({ code, language = 'cpp', label }) {
  const highlighted = useMemo(() => {
    try {
      return hljs.highlight(code.trim(), { language }).value
    } catch {
      return code.trim()
    }
  }, [code, language])

  return (
    <div className="code-block-wrapper">
      {label && <div className="code-block-header">{label}</div>}
      <pre>
        <code
          className={`hljs language-${language}`}
          dangerouslySetInnerHTML={{ __html: highlighted }}
        />
      </pre>
    </div>
  )
}

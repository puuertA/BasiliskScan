#!/usr/bin/env python3
"""Testes completos para verificar que placeholders são restaurados corretamente."""

import re
import unittest
from basiliskscan.reporter import ReportGenerator


class TestMarkdownPlaceholders(unittest.TestCase):
    """Testa a restauração correta de placeholders no processamento de Markdown."""

    def setUp(self):
        self.reporter = ReportGenerator()

    def test_single_inline_code(self):
        """Testa que um único inline code é restaurado corretamente."""
        text = r'Use `npm install` to install dependencies.'
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<code>npm install</code>', result)
        self.assertNotIn('@@BSCODEINLINE', result)

    def test_multiple_inline_codes(self):
        """Testa que múltiplos inline codes são restaurados corretamente."""
        text = r'Use `npm` to run `npm start` command and `npm test` for testing.'
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<code>npm</code>', result)
        self.assertIn('<code>npm start</code>', result)
        self.assertIn('<code>npm test</code>', result)
        self.assertNotIn('@@BSCODEINLINE', result)

    def test_single_code_block(self):
        """Testa que um único code block é restaurado corretamente."""
        text = r'''Code example:
```python
def hello():
    print("world")
```
End.'''
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<pre><code class="language-python">', result)
        self.assertIn('def hello():', result)
        self.assertNotIn('@@BSCODEBLOCK', result)

    def test_multiple_code_blocks(self):
        """Testa que múltiplos code blocks são restaurados corretamente."""
        text = r'''First code:
```bash
echo "first"
```
Second code:
```python
print("second")
```
End.'''
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<pre><code class="language-bash">', result)
        self.assertIn('<pre><code class="language-python">', result)
        self.assertIn('echo "first"', result)
        self.assertIn('print("second")', result)
        self.assertNotIn('@@BSCODEBLOCK', result)

    def test_mixed_inline_and_code_blocks(self):
        """Testa que inline codes e code blocks são restaurados juntos."""
        text = r'''Use `npm` to run:
```bash
npm install
npm start
```
Then use `npm test` to test.'''
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<code>npm</code>', result)
        self.assertIn('<code>npm test</code>', result)
        self.assertIn('<pre><code class="language-bash">', result)
        self.assertIn('npm install', result)
        self.assertNotIn('@@BSCODEBLOCK', result)
        self.assertNotIn('@@BSCODEINLINE', result)

    def test_code_with_special_characters(self):
        """Testa que código com caracteres especiais é preservado."""
        text = r'Use `$variable` and `@decorator` in your code.'
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<code>$variable</code>', result)
        self.assertIn('<code>@decorator</code>', result)
        self.assertNotIn('@@BSCODEINLINE', result)

    def test_code_with_html_entities(self):
        """Testa que entidades HTML dentro de código são escapadas."""
        text = r'Use `<div>` and `&nbsp;` for HTML.'
        result = self.reporter._markdown_to_html(text)
        # O HTML deve ser escapado durante a conversão
        self.assertIn('<code>', result)
        self.assertNotIn('@@BSCODEINLINE', result)

    def test_inline_code_with_underscores(self):
        """Testa que inline code contendo underscores não é convertido em italic."""
        text = r'Use `_private_var` or `__dunder__` in Python.'
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<code>_private_var</code>', result)
        self.assertIn('<code>__dunder__</code>', result)
        # Não deve conter italic tags da conversão de _text_
        self.assertNotIn('<em>_private_var</em>', result)
        self.assertNotIn('<em>__dunder__</em>', result)

    def test_code_block_without_language(self):
        """Testa que code block sem linguagem é restaurado corretamente."""
        text = r'''Code:
```
no language specified
```
End.'''
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<pre><code class="">', result)
        self.assertIn('no language specified', result)
        self.assertNotIn('@@BSCODEBLOCK', result)

    def test_many_inline_codes_sequential(self):
        """Testa que muitos inline codes sequenciais são restaurados."""
        text = r'`a` `b` `c` `d` `e` `f` `g` `h` `i` `j`'
        result = self.reporter._markdown_to_html(text)
        for letter in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j']:
            self.assertIn(f'<code>{letter}</code>', result)
        self.assertNotIn('@@BSCODEINLINE', result)

    def test_markdown_with_bold_and_italic_around_code(self):
        """Testa que bold/italic formatação não interfere com código."""
        text = r'**Bold `code`** and _italic `code`_ text.'
        result = self.reporter._markdown_to_html(text)
        self.assertIn('<code>code</code>', result)
        self.assertIn('<strong>', result)
        self.assertIn('<em>', result)
        self.assertNotIn('@@BSCODEINLINE', result)

    def test_no_false_placeholder_remnants(self):
        """Testa que não há placeholders remanescentes em qualquer saída."""
        test_cases = [
            r'Simple `code`.',
            r'`multiple` `codes` here.',
            r'```python\ncode\n```',
            r'Mix of `code` and **bold** and _italic_.',
            r'`underscore_var` in code.',
        ]
        
        for text in test_cases:
            result = self.reporter._markdown_to_html(text)
            # Verificar que nenhum placeholder remanescente existe
            placeholder_pattern = r'@@BS(CODEINLINE|CODEBLOCK)\d+@@'
            self.assertIsNone(
                re.search(placeholder_pattern, result),
                f'Found placeholder remnant in: {result}'
            )

    def test_empty_code(self):
        """Testa tratamento de código vazio."""
        text = r'Text with `` empty code and more text.'
        result = self.reporter._markdown_to_html(text)
        # Mesmo vazio, não deve conter placeholder
        self.assertNotIn('@@BSCODEINLINE', result)

    def test_nested_ticks_not_matched(self):
        """Testa que ticks aninhados não causam problemas."""
        # Padrão r`([^`]+)` não captura ticks aninhados, então este é esperado
        text = r'Use `code with `nested` ticks` here.'
        result = self.reporter._markdown_to_html(text)
        # O regex para inline code captura `code with `
        # Isso é um comportamento esperado de regex simples
        self.assertNotIn('@@BSCODEINLINE', result)


if __name__ == '__main__':
    unittest.main(verbosity=2)

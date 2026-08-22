#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
report_exporter.py — AI 安全分析报告导出 (Markdown / PDF)

- export_markdown(report): 生成 Markdown 文本
- export_pdf(report): 使用 reportlab 生成 PDF 字节流 (中文用内置 CID 字体 STSong-Light)
report 结构: {title, timestamp, target_type, target, analysis}
"""
import re

# ---------------------------------------------------------------------------
# 公共：把 report 组装为带元信息的文本
# ---------------------------------------------------------------------------

def _meta_block(report):
    lines = []
    lines.append('# %s' % (report.get('title') or 'AI 安全分析报告'))
    lines.append('')
    lines.append('- 生成时间: %s' % (report.get('timestamp') or ''))
    lines.append('- 报告类型: %s' % (report.get('target_type') or 'overview'))
    if report.get('target'):
        lines.append('- 分析对象: %s' % report['target'])
    lines.append('')
    lines.append('---')
    lines.append('')
    lines.append((report.get('analysis') or '').strip())
    return '\n'.join(lines)


def export_markdown(report):
    """导出 Markdown 文本"""
    return _meta_block(report)


# ---------------------------------------------------------------------------
# PDF 导出 (reportlab)
# ---------------------------------------------------------------------------

def _sanitize(text):
    """替换 CID 字体(Adobe-GB1)中可能缺失的符号，避免显示为空白/异常。"""
    repl = {
        '\u2713': '[OK]', '\u2714': '[OK]', '\u2717': '[X]', '\u2718': '[X]',
        '\u2192': '->', '\u2190': '<-', '\u2194': '<->',
        '\u2022': '-', '\u25cf': '-', '\u25cb': 'o',
        '\u00b7': '-', '\u2018': "'", '\u2019': "'",
        '\u201c': '"', '\u201d': '"', '\u2013': '-', '\u2014': '-',
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    return text


def export_pdf(report):
    """导出 PDF 字节流 (reportlab)。report['analysis'] 为 Markdown 文本。"""
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Preformatted, HRFlowable, KeepTogether
    )

    FONT = 'STSong-Light'
    try:
        pdfmetrics.registerFont(UnicodeCIDFont(FONT))
    except Exception:
        FONT = 'Helvetica'

    def S(name, **kw):
        base = dict(fontName=FONT, leading=14, alignment=TA_LEFT,
                    textColor=colors.HexColor('#1a1a1a'))
        base.update(kw)
        return ParagraphStyle(name, **base)

    styles = {
        'title': S('title', fontSize=18, leading=24, spaceAfter=6,
                   textColor=colors.HexColor('#0b66c2')),
        'meta': S('meta', fontSize=9.5, leading=14, textColor=colors.HexColor('#666666'),
                  spaceAfter=2),
        'h1': S('h1', fontSize=14, leading=20, spaceBefore=10, spaceAfter=4,
                textColor=colors.HexColor('#0b66c2')),
        'h2': S('h2', fontSize=12.5, leading=18, spaceBefore=8, spaceAfter=3,
                textColor=colors.HexColor('#135ba6')),
        'h3': S('h3', fontSize=11.5, leading=16, spaceBefore=6, spaceAfter=2),
        'body': S('body', fontSize=10.5, leading=16, spaceAfter=4),
        'quote': S('quote', fontSize=10, leading=15, leftIndent=12,
                   textColor=colors.HexColor('#555555'), spaceAfter=4),
        'li': S('li', fontSize=10.5, leading=16, leftIndent=14, spaceAfter=2),
        'li_num': S('li_num', fontSize=10.5, leading=16, leftIndent=14, spaceAfter=2),
        'code': S('code', fontSize=9, leading=12.5, leftIndent=8,
                  backColor=colors.HexColor('#f4f4f4'), borderColor=colors.HexColor('#dddddd'),
                  borderWidth=0.5, borderPadding=4, spaceAfter=6,
                  textColor=colors.HexColor('#222222')),
    }

    def esc(s):
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def inline(s):
        s = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s)
        s = re.sub(r'`(.+?)`', r'<font face="Courier">\1</font>', s)
        return s

    def md_to_flowables(md):
        flow = []
        lines = _sanitize(md).split('\n')
        n = len(lines)
        i = 0
        para_buf = []
        in_code = False
        code_buf = []

        def flush_para():
            if para_buf:
                text = ' '.join(x.strip() for x in para_buf if x.strip())
                if text:
                    flow.append(Paragraph(inline(esc(text)), styles['body']))
                para_buf.clear()

        while i < n:
            line = lines[i]
            st = line.strip()
            if st.startswith('```'):
                flush_para()
                if not in_code:
                    in_code = True
                    code_buf = []
                else:
                    in_code = False
                    flow.append(Preformatted('\n'.join(code_buf), styles['code']))
                i += 1
                continue
            if in_code:
                code_buf.append(line)
                i += 1
                continue
            if not st:
                flush_para()
                i += 1
                continue
            if st in ('---', '***', '___'):
                flush_para()
                flow.append(HRFlowable(width='100%', thickness=0.6,
                                       color=colors.HexColor('#bbbbbb'),
                                       spaceBefore=4, spaceAfter=6))
                i += 1
                continue
            if st.startswith('# '):
                flush_para(); flow.append(Paragraph(inline(esc(st[2:])), styles['h1'])); i += 1; continue
            if st.startswith('## '):
                flush_para(); flow.append(Paragraph(inline(esc(st[3:])), styles['h2'])); i += 1; continue
            if st.startswith('### '):
                flush_para(); flow.append(Paragraph(inline(esc(st[4:])), styles['h3'])); i += 1; continue
            if st.startswith('> '):
                flush_para(); flow.append(Paragraph(inline(esc(st[2:])), styles['quote'])); i += 1; continue
            m = re.match(r'^(\d+)\.\s+(.*)$', st)
            if m:
                flush_para(); flow.append(Paragraph('%s. %s' % (m.group(1), inline(esc(m.group(2)))), styles['li_num'])); i += 1; continue
            if st.startswith('- ') or st.startswith('* '):
                flush_para(); flow.append(Paragraph('- ' + inline(esc(st[2:])), styles['li'])); i += 1; continue
            para_buf.append(line)
            i += 1
        flush_para()
        if in_code and code_buf:
            flow.append(Preformatted('\n'.join(code_buf), styles['code']))
        return flow

    # 组装文档
    story = []
    story.append(Paragraph(esc(_sanitize(report.get('title') or 'AI 安全分析报告')), styles['title']))
    meta = '生成时间: %s' % (report.get('timestamp') or '')
    if report.get('target_type'):
        meta += '    报告类型: %s' % report['target_type']
    if report.get('target'):
        meta += '    分析对象: %s' % report['target']
    story.append(Paragraph(esc(_sanitize(meta)), styles['meta']))
    story.append(HRFlowable(width='100%', thickness=0.8,
                            color=colors.HexColor('#0b66c2'), spaceBefore=2, spaceAfter=8))
    story.extend(md_to_flowables(report.get('analysis') or ''))

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=report.get('title') or 'AI 安全分析报告',
        author='linmon',
    )
    doc.build(story)
    return buf.getvalue()

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
        SimpleDocTemplate, Paragraph, Spacer, Preformatted, HRFlowable,
        KeepTogether, Table, TableStyle,
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
        'th': S('th', fontSize=9.5, leading=13, alignment=TA_LEFT,
                textColor=colors.HexColor('#ffffff'),
                backColor=colors.HexColor('#0b66c2'),
                borderPadding=4),
        'td': S('td', fontSize=9.5, leading=13, alignment=TA_LEFT,
                borderPadding=4),
    }

    def esc(s):
        """转义 XML 特殊字符（必须在 inline 之前调用）"""
        if not s:
            return s
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def inline(s):
        """将 Markdown 行内标记转为 reportlab XML 标签。须在 esc 之后调用。"""
        if not s:
            return s
        # 加粗 **text** 或 __text__
        s = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s)
        s = re.sub(r'__(.+?)__', r'<b>\1</b>', s)
        # 斜体 *text* 或 _text_（避免与加粗冲突：只匹配单个 * 且后面非空格）
        s = re.sub(r'(?<!\*)\*(?!\s)(.+?)(?<!\s)\*(?!\*)', r'<i>\1</i>', s)
        # 删除线 ~~text~~
        s = re.sub(r'~~(.+?)~~', r'<strike>\1</strike>', s)
        # 行内代码 `code`
        s = re.sub(r'`(.+?)`', r'<font face="Courier">\1</font>', s)
        # 链接 [text](url) → 只保留 text 并加下划线
        s = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'<u>\1</u>', s)
        return s

    def inline_html(text):
        """先转义再渲染行内标记"""
        return inline(esc(text))

    # ---- 表格解析 ----
    def parse_table_row(line):
        """解析 markdown 表格行，返回单元格列表。"""
        line = line.strip()
        if line.startswith('|'):
            line = line[1:]
        if line.endswith('|'):
            line = line[:-1]
        return [cell.strip() for cell in line.split('|')]

    def is_separator_row(line):
        """判断是否为表格分隔行 |---|---|"""
        cells = parse_table_row(line)
        if not cells:
            return False
        return all(re.match(r'^:?-{2,}:?$', c) for c in cells)

    def build_table(header_cells, rows):
        """用 reportlab Table 构建带样式的表格，返回 flowable。"""
        col_count = len(header_cells)

        # 表头 Paragraph
        header_paras = [Paragraph(inline_html(c), styles['th']) for c in header_cells]

        # 数据行 Paragraph
        data = [header_paras]
        for row in rows:
            # 补齐列数
            while len(row) < col_count:
                row.append('')
            data.append([Paragraph(inline_html(c), styles['td']) for c in row[:col_count]])

        table = Table(data, hAlign='LEFT')
        table.setStyle(TableStyle([
            # 表头背景
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0b66c2')),
            # 网格线
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            # 表头字体
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            # 内边距
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            # 斑马纹（偶数行浅灰）
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#f6f8fa')]),
            # 垂直对齐
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        return table

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
                    flow.append(Paragraph(inline_html(text), styles['body']))
                para_buf.clear()

        while i < n:
            line = lines[i]
            st = line.strip()

            # 代码块
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

            # 空行
            if not st:
                flush_para()
                i += 1
                continue

            # 水平分割线
            if st in ('---', '***', '___'):
                flush_para()
                flow.append(HRFlowable(width='100%', thickness=0.6,
                                       color=colors.HexColor('#bbbbbb'),
                                       spaceBefore=4, spaceAfter=6))
                i += 1
                continue

            # 表格检测：当前行含 | 且下一行是分隔行
            if '|' in line and i + 1 < n and is_separator_row(lines[i + 1].strip()):
                flush_para()
                header_cells = parse_table_row(st)
                # 跳过分隔行
                i += 2
                rows = []
                while i < n:
                    row_line = lines[i].strip()
                    if not row_line or '|' not in row_line:
                        break
                    rows.append(parse_table_row(row_line))
                    i += 1
                if header_cells and rows:
                    flow.append(build_table(header_cells, rows))
                    flow.append(Spacer(1, 6))
                continue

            # 标题
            if st.startswith('# '):
                flush_para(); flow.append(Paragraph(inline_html(st[2:]), styles['h1'])); i += 1; continue
            if st.startswith('## '):
                flush_para(); flow.append(Paragraph(inline_html(st[3:]), styles['h2'])); i += 1; continue
            if st.startswith('### '):
                flush_para(); flow.append(Paragraph(inline_html(st[4:]), styles['h3'])); i += 1; continue
            if st.startswith('#### '):
                flush_para(); flow.append(Paragraph(inline_html(st[5:]), styles['h3'])); i += 1; continue

            # 引用
            if st.startswith('> '):
                flush_para(); flow.append(Paragraph(inline_html(st[2:]), styles['quote'])); i += 1; continue

            # 有序列表
            m = re.match(r'^(\d+)\.\s+(.*)$', st)
            if m:
                flush_para()
                flow.append(Paragraph('%s. %s' % (m.group(1), inline_html(m.group(2))), styles['li_num']))
                i += 1; continue

            # 无序列表
            if st.startswith('- ') or st.startswith('* '):
                flush_para()
                flow.append(Paragraph('- ' + inline_html(st[2:]), styles['li']))
                i += 1; continue

            # 普通段落
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

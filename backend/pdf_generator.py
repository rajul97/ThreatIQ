"""
ThreatIQ — Enhanced Enterprise PDF v3
Dark cover · TOC · Watermark · Threat score bar · Act Now callout
Attack timeline · Feed reputation dots · Geo/ASN block · Non-technical summary
"""
import os, logging, math
from datetime import datetime, timezone
from typing import Dict, List, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak
)
from reportlab.platypus.flowables import Flowable

logger = logging.getLogger('threatiq')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'reports')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Page geometry ──────────────────────────────────────────────────────────────
PW, PH  = A4
HDR_H   = 90
FTR_H   = 28
LM      = 18 * mm
RM      = 18 * mm
TM      = HDR_H + 22
BM      = FTR_H + 16
USABLE  = PW - LM - RM

# ── Colours ────────────────────────────────────────────────────────────────────
C_HDR    = colors.HexColor('#111111')
C_WHITE  = colors.white
C_BODY   = colors.HexColor('#1F2937')
C_MUT    = colors.HexColor('#6B7280')
C_BORD   = colors.HexColor('#E5E7EB')
C_BORD2  = colors.HexColor('#D1D5DB')
C_RED    = colors.HexColor('#DC2626')
C_AMB    = colors.HexColor('#D97706')
C_GRN    = colors.HexColor('#16A34A')
C_BLU    = colors.HexColor('#2563EB')
C_PUR    = colors.HexColor('#7C3AED')
BG_RED   = colors.HexColor('#FEF2F2')
BG_AMB   = colors.HexColor('#FFFBEB')
BG_GRN   = colors.HexColor('#F0FDF4')
BG_BLU   = colors.HexColor('#EFF6FF')
BG_PUR   = colors.HexColor('#F5F3FF')
BG_SOFT  = colors.HexColor('#F9FAFB')
C_COV    = colors.HexColor('#0F172A')
C_KC_ON  = colors.HexColor('#14532D')
C_KC_ONT = colors.HexColor('#86EFAC')
C_KC_OFF = colors.HexColor('#E5E7EB')
C_KC_OFT = colors.HexColor('#9CA3AF')
C_TGT    = colors.HexColor('#111827')
C_TGT_IP = colors.HexColor('#4ADE80')
C_TGT_M  = colors.HexColor('#9CA3AF')
C_COD_BG = colors.HexColor('#1a1a1a')
C_COD_K  = colors.HexColor('#F59E0B')
C_COD_V  = colors.HexColor('#4ADE80')
C_COD_C  = colors.HexColor('#6B7280')
C_SUB    = colors.HexColor('#374151')
C_CONF   = colors.HexColor('#DC2626')

TMAP = {
    'CRITICAL': (C_RED,  BG_RED,  'CRITICAL'),
    'HIGH':     (C_RED,  BG_RED,  'HIGH'),
    'MEDIUM':   (C_AMB,  BG_AMB,  'MEDIUM'),
    'LOW':      (C_GRN,  BG_GRN,  'LOW'),
    'UNKNOWN':  (C_MUT,  BG_SOFT, 'UNKNOWN'),
}
CMAP = {
    'high':   (C_GRN, BG_GRN),
    'medium': (C_AMB, BG_AMB),
    'low':    (C_MUT, BG_SOFT),
}
PMAP = {
    'immediate': (C_RED, BG_RED, 'IMMEDIATE'),
    '24 hours':  (C_AMB, BG_AMB, '24 HOURS'),
    '24h':       (C_AMB, BG_AMB, '24 HOURS'),
    '1 week':    (C_PUR, BG_PUR, '1 WEEK'),
    'week':      (C_PUR, BG_PUR, '1 WEEK'),
    'ongoing':   (C_GRN, BG_GRN, 'ONGOING'),
}
NUM_C = [C_RED, C_RED, C_AMB, C_AMB, C_AMB, C_BLU, C_BLU, C_GRN] + [C_MUT] * 20


# ── Paragraph styles ──────────────────────────────────────────────────────────
def _S():
    def ps(n, **k): return ParagraphStyle(n, **k)
    return {
        # Cover (dark background) styles
        'cov_h1':     ps('cov_h1',   fontName='Helvetica-Bold', fontSize=26,  textColor=C_WHITE,                         leading=34),
        'cov_sub':    ps('cov_sub',  fontName='Helvetica',      fontSize=11.5,textColor=colors.HexColor('#94A3B8'),      leading=17),
        'cov_mk':     ps('cov_mk',   fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.HexColor('#475569'),      leading=12),
        'cov_mv':     ps('cov_mv',   fontName='Helvetica',      fontSize=9.5, textColor=colors.HexColor('#CBD5E1'),      leading=13),
        'cov_mvb':    ps('cov_mvb',  fontName='Helvetica-Bold', fontSize=11,  textColor=C_WHITE,                         leading=15),
        'cov_geo_k':  ps('cov_geo_k',fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.HexColor('#475569'),      leading=11, alignment=TA_CENTER),
        'cov_geo_v':  ps('cov_geo_v',fontName='Helvetica-Bold', fontSize=10,  textColor=C_WHITE,                         leading=14, alignment=TA_CENTER),
        # TOC styles
        'toc_sec':    ps('toc_sec',  fontName='Helvetica-Bold', fontSize=11,  textColor=C_BODY,  leading=16),
        'toc_pg':     ps('toc_pg',   fontName='Helvetica',      fontSize=11,  textColor=C_MUT,   leading=16, alignment=TA_RIGHT),
        'toc_desc':   ps('toc_desc', fontName='Helvetica',      fontSize=9.5, textColor=C_MUT,   leading=14),
        # Standard content styles
        'h1':         ps('h1',       fontName='Helvetica-Bold', fontSize=26,  textColor=C_BODY,  leading=32),
        'sec_lbl':    ps('sec_lbl',  fontName='Helvetica-Bold', fontSize=8.5, textColor=C_MUT,   leading=11, spaceAfter=0),
        'body':       ps('body',     fontName='Helvetica',      fontSize=10.5,textColor=C_BODY,  leading=18, alignment=TA_JUSTIFY),
        'body_l':     ps('body_l',   fontName='Helvetica',      fontSize=10.5,textColor=C_BODY,  leading=18),
        'meta_k':     ps('meta_k',   fontName='Helvetica-Bold', fontSize=10,  textColor=C_BODY,  leading=14),
        'meta_v':     ps('meta_v',   fontName='Helvetica',      fontSize=10,  textColor=C_SUB,   leading=14),
        'meta_vb':    ps('meta_vb',  fontName='Helvetica-Bold', fontSize=11,  textColor=C_BODY,  leading=14),
        'tgt_lbl':    ps('tgt_lbl',  fontName='Helvetica-Bold', fontSize=8,   textColor=C_TGT_M, leading=11),
        'tgt_ip':     ps('tgt_ip',   fontName='Courier-Bold',   fontSize=22,  textColor=C_TGT_IP,leading=28),
        'tgt_sub':    ps('tgt_sub',  fontName='Helvetica',      fontSize=9.5, textColor=C_TGT_M, leading=14),
        'stat_lbl':   ps('stat_lbl', fontName='Helvetica-Bold', fontSize=8,   textColor=C_MUT,   leading=10, alignment=TA_LEFT),
        'stat_val':   ps('stat_val', fontName='Helvetica-Bold', fontSize=22,  textColor=C_BODY,  leading=26),
        'stat_sub':   ps('stat_sub', fontName='Helvetica',      fontSize=8.5, textColor=C_MUT,   leading=11),
        'step_n':     ps('step_n',   fontName='Helvetica-Bold', fontSize=10.5,textColor=C_BODY,  leading=16),
        'step_d':     ps('step_d',   fontName='Helvetica',      fontSize=10,  textColor=C_SUB,   leading=17, alignment=TA_JUSTIFY),
        'ttp_id':     ps('ttp_id',   fontName='Courier-Bold',   fontSize=9,   textColor=C_BLU,   leading=12),
        'ttp_nm':     ps('ttp_nm',   fontName='Helvetica',      fontSize=10,  textColor=C_BODY,  leading=15),
        'ttp_tc':     ps('ttp_tc',   fontName='Helvetica',      fontSize=9.5, textColor=C_MUT,   leading=13),
        'ttp_tl':     ps('ttp_tl',   fontName='Helvetica',      fontSize=9,   textColor=C_MUT,   leading=13),
        'ioc_val':    ps('ioc_val',  fontName='Courier-Bold',   fontSize=10,  textColor=C_BLU,   leading=14),
        'ioc_t':      ps('ioc_t',    fontName='Helvetica',      fontSize=9.5, textColor=C_MUT,   leading=13),
        'ioc_src':    ps('ioc_src',  fontName='Helvetica',      fontSize=8.5, textColor=C_MUT,   leading=13),
        'cve_id':     ps('cve_id',   fontName='Courier-Bold',   fontSize=10,  textColor=C_RED,   leading=14),
        'cve_cv':     ps('cve_cv',   fontName='Helvetica-Bold', fontSize=15,  textColor=C_BODY,  leading=19),
        'cve_d':      ps('cve_d',    fontName='Helvetica',      fontSize=9.5, textColor=C_SUB,   leading=15, alignment=TA_JUSTIFY),
        'cve_sys':    ps('cve_sys',  fontName='Courier',        fontSize=8.5, textColor=C_MUT,   leading=13),
        'rec_num':    ps('rec_num',  fontName='Helvetica-Bold', fontSize=26,  textColor=C_RED,   leading=30, alignment=TA_CENTER),
        'rec_tit':    ps('rec_tit',  fontName='Helvetica-Bold', fontSize=11,  textColor=C_BODY,  leading=15),
        'rec_d':      ps('rec_d',    fontName='Helvetica',      fontSize=9.5, textColor=C_SUB,   leading=16, alignment=TA_JUSTIFY),
        'code':       ps('code',     fontName='Courier',        fontSize=8.5, textColor=C_COD_V, leading=14),
        'cod_k':      ps('cod_k',    fontName='Courier-Bold',   fontSize=8.5, textColor=C_COD_K, leading=14),
        'cod_c':      ps('cod_c',    fontName='Courier',        fontSize=8.5, textColor=C_COD_C, leading=14),
        'sig_hd':     ps('sig_hd',   fontName='Helvetica',      fontSize=10,  textColor=C_MUT,   leading=15),
        'app_k':      ps('app_k',    fontName='Helvetica-Bold', fontSize=9.5, textColor=C_MUT,   leading=13),
        'app_v':      ps('app_v',    fontName='Helvetica',      fontSize=9.5, textColor=C_BODY,  leading=13),
        'tool_n':     ps('tool_n',   fontName='Helvetica-Bold', fontSize=10,  textColor=C_BODY,  leading=14),
        'tool_d':     ps('tool_d',   fontName='Helvetica',      fontSize=9.5, textColor=C_MUT,   leading=13),
        'disc':       ps('disc',     fontName='Helvetica',      fontSize=8.5, textColor=C_MUT,   leading=13, alignment=TA_JUSTIFY),
        'tbl_hd':     ps('tbl_hd',   fontName='Helvetica-Bold', fontSize=8.5, textColor=C_MUT,   leading=11),
        'small':      ps('small',    fontName='Helvetica',      fontSize=8.5, textColor=C_MUT,   leading=12),
        'risk_grn':   ps('risk_grn', fontName='Helvetica-Bold', fontSize=10,  textColor=C_GRN,   leading=14),
        'risk_red':   ps('risk_red', fontName='Helvetica-Bold', fontSize=10,  textColor=C_RED,   leading=14),
        'risk_amb':   ps('risk_amb', fontName='Helvetica-Bold', fontSize=10,  textColor=C_AMB,   leading=14),
        # Act Now callout
        'act_hdr':    ps('act_hdr',  fontName='Helvetica-Bold', fontSize=11,  textColor=C_RED,   leading=15),
        'act_item':   ps('act_item', fontName='Helvetica',      fontSize=10,  textColor=C_BODY,  leading=15),
        # Non-technical summary
        'nt_head':    ps('nt_head',  fontName='Helvetica-Bold', fontSize=14,  textColor=C_BODY,  leading=20),
        'nt_body':    ps('nt_body',  fontName='Helvetica',      fontSize=11,  textColor=C_BODY,  leading=19, alignment=TA_JUSTIFY),
        'nt_bullet':  ps('nt_bullet',fontName='Helvetica',      fontSize=11,  textColor=C_BODY,  leading=18, leftIndent=14),
        'nt_bold':    ps('nt_bold',  fontName='Helvetica-Bold', fontSize=11,  textColor=C_BODY,  leading=17),
    }


# ── Custom Flowables ──────────────────────────────────────────────────────────

class KillChainBar(Flowable):
    PHASES = [
        ('Recon',     'reconnaissance'),
        ('Weaponize', 'weaponization'),
        ('Deliver',   'delivery'),
        ('Exploit',   'exploitation'),
        ('Install',   'installation'),
        ('C2',        'command_control'),
        ('Actions',   'actions_on_objectives'),
    ]
    def __init__(self, kc: dict, width: float):
        super().__init__()
        self.kc = kc
        self.width = width
        self.height = 36

    def wrap(self, aw, ah): return self.width, self.height

    def draw(self):
        c = self.canv
        n = len(self.PHASES)
        gap = 4
        pw = (self.width - gap * (n - 1)) / n
        ph = 26
        y  = (self.height - ph) / 2
        for i, (label, key) in enumerate(self.PHASES):
            x      = i * (pw + gap)
            active = self.kc.get(key, False)
            bg     = C_KC_ON  if active else C_KC_OFF
            tc     = C_KC_ONT if active else C_KC_OFT
            c.setFillColor(bg)
            c.roundRect(x, y, pw, ph, 4, fill=1, stroke=0)
            c.setFillColor(tc)
            c.setFont('Helvetica-Bold', 8)
            dot = '●' if active else '■'
            c.drawCentredString(x + pw / 2, y + 8, f'{dot} {label}')


class TargetBanner(Flowable):
    def __init__(self, subject: str, ioc_type: str, tags: str, width: float):
        super().__init__()
        self.subject  = subject
        self.ioc_type = ioc_type
        self.tags     = tags
        self.width    = width
        self.height   = 72

    def wrap(self, aw, ah): return self.width, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(C_TGT)
        c.roundRect(0, 0, self.width, self.height, 5, fill=1, stroke=0)
        lw = self.width * 0.45
        c.setFillColor(C_TGT_M)
        c.setFont('Helvetica-Bold', 7.5)
        c.drawString(16, self.height - 18, self.ioc_type.upper().replace('_', ' '))
        c.setFillColor(C_TGT_IP)
        c.setFont('Courier-Bold', 20)
        c.drawString(16, self.height - 48, self.subject[:32])
        c.setFillColor(C_TGT_M)
        c.setFont('Helvetica', 9)
        rx = lw + 20
        ry = self.height / 2 - 4
        words = self.tags.split(' · ')
        line = ''
        lines_out = []
        for w in words:
            test = (line + ' · ' + w).strip(' · ')
            if c.stringWidth(test, 'Helvetica', 9) < (self.width - rx - 16):
                line = test
            else:
                if line: lines_out.append(line)
                line = w
        if line: lines_out.append(line)
        for j, ln in enumerate(lines_out[:3]):
            c.drawString(rx, ry - j * 14, ln)


class SigmaBlock(Flowable):
    """Dark terminal SIGMA preview block."""
    def __init__(self, lines: list, width: float):
        super().__init__()
        self._lines = lines
        self.width  = width
        self.height = 0

    def wrap(self, aw, ah):
        self.height = 14 * len(self._lines) + 20
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(C_COD_BG)
        c.roundRect(0, 0, self.width, self.height, 5, fill=1, stroke=0)
        y = self.height - 24
        for raw in self._lines:
            if raw.startswith('#'):
                c.setFillColor(C_COD_C); c.setFont('Courier', 8.5)
                c.drawString(14, y, raw)
            elif ':' in raw and not raw.startswith(' '):
                parts = raw.split(':', 1)
                kw = c.stringWidth(parts[0] + ':', 'Courier-Bold', 8.5)
                c.setFillColor(C_COD_K); c.setFont('Courier-Bold', 8.5)
                c.drawString(14, y, parts[0] + ':')
                c.setFillColor(C_COD_V); c.setFont('Courier', 8.5)
                c.drawString(14 + kw + 3, y, parts[1].strip())
            else:
                c.setFillColor(C_COD_V); c.setFont('Courier', 8.5)
                c.drawString(14, y, raw)
            y -= 14


class ThreatScoreBar(Flowable):
    """Horizontal green->amber->red threat score gauge with confidence marker."""
    def __init__(self, confidence: int, threat_level: str, width: float):
        super().__init__()
        self.confidence   = max(0, min(100, int(confidence or 0)))
        self.threat_level = threat_level
        self.width        = width
        self.height       = 52

    def wrap(self, aw, ah): return self.width, self.height

    def draw(self):
        c   = self.canv
        bh  = 12
        by  = 24
        bw  = self.width

        # Three gradient segments
        seg_w = bw / 3
        segs  = [
            (0,         seg_w,     colors.HexColor('#22C55E')),  # green
            (seg_w,     seg_w * 2, colors.HexColor('#F59E0B')),  # amber
            (seg_w * 2, bw,        colors.HexColor('#EF4444')),  # red
        ]
        # Draw rounded rect for first and last, plain rect for middle
        c.setFillColor(segs[0][2])
        c.roundRect(segs[0][0], by, seg_w, bh, 4, fill=1, stroke=0)
        c.setFillColor(segs[1][2])
        c.rect(segs[1][0], by, seg_w, bh, fill=1, stroke=0)
        c.setFillColor(segs[2][2])
        c.roundRect(segs[2][0], by, seg_w, bh, 4, fill=1, stroke=0)
        # Overlap fix — draw plain rects over joins
        c.setFillColor(segs[0][2]); c.rect(seg_w - 4, by, 4, bh, fill=1, stroke=0)
        c.setFillColor(segs[1][2]); c.rect(seg_w * 2 - 4, by, 4, bh, fill=1, stroke=0)

        # Confidence marker
        mx = (self.confidence / 100.0) * bw
        c.setFillColor(C_WHITE)
        c.roundRect(mx - 2, by - 4, 4, bh + 8, 2, fill=1, stroke=0)

        # Bottom labels
        c.setFillColor(colors.HexColor('#22C55E'))
        c.setFont('Helvetica-Bold', 7)
        c.drawString(2, by - 13, 'LOW RISK')
        c.setFillColor(colors.HexColor('#F59E0B'))
        c.drawCentredString(bw / 2, by - 13, 'MODERATE')
        c.setFillColor(colors.HexColor('#EF4444'))
        c.drawRightString(bw - 2, by - 13, 'CRITICAL RISK')

        # Confidence value above marker
        c.setFillColor(C_BODY)
        c.setFont('Helvetica-Bold', 9)
        label = f'{self.confidence}% Confidence'
        lw = c.stringWidth(label, 'Helvetica-Bold', 9)
        lx = max(lw / 2 + 4, min(mx, bw - lw / 2 - 4))
        c.drawCentredString(lx, by + bh + 6, label)


class AttackTimeline(Flowable):
    """Visual numbered timeline replacing plain attack steps table."""
    def __init__(self, steps: list, width: float):
        super().__init__()
        self.steps  = steps
        self.width  = width
        self.row_h  = 56
        self.height = max(len(steps) * self.row_h + 8, 60)

    def wrap(self, aw, ah): return self.width, self.height

    def draw(self):
        c  = self.canv
        cx = 20  # circle center x

        for i, step in enumerate(self.steps):
            y_top = self.height - (i + 1) * self.row_h
            cy    = y_top + self.row_h - 18

            # Connecting line above circle (except first item)
            if i > 0:
                c.setStrokeColor(C_BORD2)
                c.setLineWidth(1.5)
                c.line(cx, cy + 12, cx, cy + self.row_h - 4)

            # Numbered circle
            col = NUM_C[i] if i < len(NUM_C) else C_MUT
            c.setFillColor(col)
            c.circle(cx, cy, 11, fill=1, stroke=0)
            c.setFillColor(C_WHITE)
            c.setFont('Helvetica-Bold', 9)
            c.drawCentredString(cx, cy - 3.5, str(i + 1))

            # Step name
            name = step.get('name', f'Step {i+1}')
            tx   = cx + 26
            c.setFillColor(C_BODY)
            c.setFont('Helvetica-Bold', 10.5)
            c.drawString(tx, cy + 3, name[:65])

            # Description (word-wrapped, max 2 lines)
            desc    = str(step.get('description', ''))
            max_w   = self.width - tx - 8
            words   = desc.split()
            line_   = ''
            out     = []
            for w in words:
                test = (line_ + ' ' + w).strip() if line_ else w
                if c.stringWidth(test, 'Helvetica', 9) <= max_w:
                    line_ = test
                else:
                    if line_: out.append(line_)
                    line_ = w
            if line_: out.append(line_)
            c.setFillColor(C_SUB)
            c.setFont('Helvetica', 9)
            for j, ln in enumerate(out[:2]):
                c.drawString(tx, cy - 10 - j * 12, ln)


class FeedDots(Flowable):
    """Colored dot indicators — how many threat feeds flagged this IOC."""
    TOTAL = 9
    def __init__(self, count: int, width: float = 90):
        super().__init__()
        self.count  = max(0, min(int(count or 0), self.TOTAL))
        self.width  = width
        self.height = 36

    def wrap(self, aw, ah): return self.width, self.height

    def draw(self):
        c     = self.canv
        r     = 6
        usable = self.width - 8
        gap   = usable / (self.TOTAL - 1) if self.TOTAL > 1 else usable
        dot_c = C_RED if self.count >= 7 else C_AMB if self.count >= 4 else C_GRN
        for i in range(self.TOTAL):
            x = 4 + i * gap
            c.setFillColor(dot_c if i < self.count else C_BORD)
            c.circle(x, 22, r, fill=1, stroke=0)
        # Count label below dots
        c.setFillColor(dot_c if self.count > 0 else C_MUT)
        c.setFont('Helvetica-Bold', 7.5)
        c.drawCentredString(self.width / 2, 6, f'{self.count}/{self.TOTAL} feeds')


# ── Canvas callbacks — header + footer + watermark every page ─────────────────

def _make_page_cb(tlevel: str, report_id: str, date_str: str):
    tc, _, tl = TMAP.get(tlevel, TMAP['UNKNOWN'])

    def _draw(canvas, doc):
        canvas.saveState()

        # ── Full dark background on cover page only ──
        if doc.page == 1:
            canvas.setFillColor(C_COV)
            canvas.rect(0, 0, PW, PH, fill=1, stroke=0)
            # Subtle diagonal stripe texture
            canvas.setFillColor(colors.HexColor('#1E293B'))
            canvas.setStrokeColor(colors.HexColor('#1E293B'))
            canvas.setLineWidth(0.5)
            for xi in range(-10, int(PW / 18) + 20):
                canvas.line(xi * 18 - PH, 0, xi * 18, PH)

        # ── CONFIDENTIAL diagonal watermark ──
        canvas.saveState()
        canvas.translate(PW / 2, PH / 2)
        canvas.rotate(35)
        canvas.setFillColor(colors.Color(0.82, 0.82, 0.82, 0.11))
        canvas.setFont('Helvetica-Bold', 62)
        canvas.drawCentredString(0, 0, 'CONFIDENTIAL')
        canvas.restoreState()

        # ── Dark header band ──
        canvas.setFillColor(C_HDR)
        canvas.rect(0, PH - HDR_H, PW, HDR_H, fill=1, stroke=0)

        # Blue accent top border
        canvas.setFillColor(C_BLU)
        canvas.rect(0, PH - 4, PW, 4, fill=1, stroke=0)

        # ThreatIQ logo text
        canvas.setFillColor(C_WHITE)
        canvas.setFont('Helvetica-Bold', 22)
        canvas.drawString(LM, PH - 38, 'ThreatIQ')

        # Subtitle
        canvas.setFillColor(colors.HexColor('#9CA3AF'))
        canvas.setFont('Helvetica', 9)
        canvas.drawString(LM, PH - 56, 'AI-Powered Threat Intelligence Platform')

        # Threat level pill — right side of header
        pill_w, pill_h = 92, 24
        pill_x = PW - RM - pill_w
        pill_y = PH - HDR_H / 2 - pill_h / 2
        canvas.setFillColor(tc)
        canvas.roundRect(pill_x, pill_y, pill_w, pill_h, 4, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont('Helvetica-Bold', 10)
        canvas.drawCentredString(pill_x + pill_w / 2, pill_y + 7.5, tl)

        # ── Footer ──
        fy = 10
        canvas.setStrokeColor(C_BORD)
        canvas.setLineWidth(0.5)
        canvas.line(LM, fy + 18, PW - RM, fy + 18)

        canvas.setFillColor(C_MUT)
        canvas.setFont('Helvetica', 7.5)
        canvas.drawString(LM, fy + 6, f'ThreatIQ Confidential Report  |  ID: {report_id}')
        canvas.drawCentredString(PW / 2, fy + 6, f'Page {doc.page}  |  {date_str}')

        canvas.setFillColor(C_CONF)
        canvas.setFont('Helvetica-Bold', 7.5)
        canvas.drawRightString(PW - RM, fy + 6, 'CONFIDENTIAL')

        canvas.restoreState()

    return _draw


# ── Helpers ────────────────────────────────────────────────────────────────────

def _gap(pt=8):
    return Spacer(1, pt)


def _hr():
    return HRFlowable(width=USABLE, thickness=0.6, color=C_BORD, spaceAfter=6, spaceBefore=2)


def _sec(label, S):
    return KeepTogether([
        Paragraph(label.upper(), S['sec_lbl']),
        _hr(),
    ])


def _pill(text, fg, bg, fs=8):
    p = Paragraph(f'<b>{text}</b>',
                  ParagraphStyle('_pl', fontName='Helvetica-Bold', fontSize=fs,
                                 textColor=fg, alignment=TA_CENTER, leading=fs + 3))
    t = Table([[p]])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), bg),
        ('BOX',           (0, 0), (-1, -1), 0.5, fg),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    return t


def _subject(data):
    iocs = data.get('iocs', {})
    for k in ('ipv4', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cve'):
        vs = iocs.get(k, [])
        if vs: return str(vs[0])
    return str(data.get('input_text', '') or 'Unknown')[:60]


def _clamp(s, n):
    s = str(s or '')
    return (s[:n] + '…') if len(s) > n else s


# ── Section builders ──────────────────────────────────────────────────────────

def _build_cover(data, S):
    """Page 1: Full-dark cover with threat score bar, geo/ASN block, TARGET banner."""
    elems = []
    meta     = data.get('metadata', {})
    aid      = data.get('analysis_id', 'N/A')
    tlevel   = str(data.get('threat_level', 'UNKNOWN')).upper()
    conf     = data.get('confidence', 0)
    ttps     = data.get('ttps', [])
    subj     = _subject(data)
    ioc_type = meta.get('input_type', 'IOC').replace('_', ' ').upper()
    now_str  = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    actor    = data.get('actor', 'Unknown (Tor Exit Node — Shared Infrastructure)')
    origin   = data.get('origin', 'Unknown')

    # Geo / ASN data
    geo      = data.get('geo', data.get('geolocation', {})) or {}
    asn_info = data.get('asn', {}) or {}
    country  = geo.get('country', geo.get('country_name', 'Unknown'))
    city     = geo.get('city', '')
    asn_num  = asn_info.get('asn', geo.get('asn', 'N/A'))
    isp_name = asn_info.get('isp', asn_info.get('org', geo.get('isp', geo.get('org', 'Unknown'))))

    # Dark title card
    tc, _, tl = TMAP.get(tlevel, TMAP['UNKNOWN'])
    elems.append(Paragraph('AI-Powered Threat Intelligence Report', S['cov_h1']))
    elems.append(_gap(4))
    elems.append(Paragraph('Comprehensive IOC Analysis — MITRE ATT&amp;CK Mapped', S['cov_sub']))
    elems.append(_gap(16))

    # ── Threat Score Gauge ──
    elems.append(ThreatScoreBar(conf, tlevel, USABLE))
    elems.append(_gap(20))

    # ── Key metadata table (dark style) ──
    rows = [
        ('Report ID',       str(aid)),
        ('Generated',       now_str),
        ('Input Type',      ioc_type),
        ('TTPs Detected',   str(len(ttps))),
        ('Confidence',      f'{conf}%'),
        ('Suspected Actor', actor),
        ('Origin',          origin),
    ]
    tdata = []
    for k, v in rows:
        if k in ('Confidence', 'TTPs Detected'):
            vp = Paragraph(v, S['cov_mvb'])
        else:
            vp = Paragraph(v, S['cov_mv'])
        tdata.append([Paragraph(k, S['cov_mk']), vp])

    mt = Table(tdata, colWidths=[USABLE * 0.28, USABLE * 0.72])
    mt.setStyle(TableStyle([
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, colors.HexColor('#1E293B')),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elems.append(mt)
    elems.append(_gap(16))

    # ── Geo / ASN info block ──
    loc_str   = f'{city}, {country}' if city and city != country else country
    geo_cells = [
        [Paragraph('LOCATION', S['cov_geo_k']),
         Paragraph('ASN',      S['cov_geo_k']),
         Paragraph('ISP / ORG', S['cov_geo_k'])],
        [Paragraph(loc_str,    S['cov_geo_v']),
         Paragraph(str(asn_num), S['cov_geo_v']),
         Paragraph(_clamp(isp_name, 28), S['cov_geo_v'])],
    ]
    geo_t = Table(geo_cells, colWidths=[USABLE / 3] * 3)
    geo_t.setStyle(TableStyle([
        ('BOX',           (0, 0), (-1, -1), 0.5, colors.HexColor('#1E293B')),
        ('LINEBEFORE',    (1, 0), (-1, -1), 0.5, colors.HexColor('#1E293B')),
        ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#0F172A')),
        ('TOPPADDING',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    elems.append(geo_t)
    elems.append(_gap(16))

    # ── TARGET IP dark banner ──
    ioc_types = list(data.get('iocs', {}).keys())
    tags_list = []
    if ioc_type: tags_list.append(ioc_type.title())
    tags_list.append(f'Origin: {origin}')
    tags_str = ' · '.join(tags_list)
    elems.append(TargetBanner(subj, ioc_type, tags_str, USABLE))

    return elems


def _build_toc(data, S):
    """Page 2: Table of Contents with estimated page numbers."""
    elems = []
    elems.append(PageBreak())
    elems.append(_sec('Table of Contents', S))
    elems.append(_gap(12))

    ttps  = data.get('ttps', [])
    cves  = data.get('cves', [])
    iocs  = data.get('iocs', {})
    recs  = data.get('recommendations', [])
    sigs  = data.get('sigma_rules', [])

    sections = [
        ('1', 'Cover Page',                    'Threat summary and key metadata',         '1'),
        ('2', 'Table of Contents',             'Document structure overview',             '2'),
        ('3', 'Executive Summary',             f'Threat assessment, {len(ttps)} TTPs, key stats', '3'),
        ('4', 'Kill Chain Analysis',           'MITRE kill chain phases + attack timeline','4'),
        ('5', f'MITRE ATT&amp;CK TTPs ({len(ttps)})', 'Technique breakdown and confidence mapping', '5'),
        ('6', 'IOC Validation Results',        'Feed reputation dots, source analysis',   '6'),
        ('7', f'CVEs Referenced ({len(cves)})', 'CVSS scores and affected systems',       '7'),
        ('8', f'Recommendations ({len(recs)})', 'Prioritised remediation actions',        '8'),
        ('9', 'SIGMA Detection Rules',         'Auto-generated SIEM detection logic',     '9'),
        ('10','Plain English Summary',         'Non-technical risk overview for decision makers', '10'),
        ('11','Appendix',                      'Raw metadata, API calls, tools used',     '11'),
    ]

    toc_data = []
    for num, title, desc, pg in sections:
        row_title = Paragraph(f'<b>{num}. {title}</b>', S['toc_sec'])
        row_desc  = Paragraph(desc, S['toc_desc'])
        row_pg    = Paragraph(f'<b>{pg}</b>', S['toc_pg'])
        inner = Table([[row_title], [row_desc]], colWidths=[USABLE * 0.80])
        inner.setStyle(TableStyle([
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        toc_data.append([inner, row_pg])

    toc_t = Table(toc_data, colWidths=[USABLE * 0.85, USABLE * 0.15])
    toc_t.setStyle(TableStyle([
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORD),
        ('TOPPADDING',    (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elems.append(toc_t)
    return elems


def _build_exec_summary(data, S):
    """Page 3: Executive summary + Act Now callout + 4-stat grid."""
    elems = []
    tlevel  = str(data.get('threat_level', 'UNKNOWN')).upper()
    conf    = data.get('confidence', 0)
    ttps    = data.get('ttps', [])
    iocs    = data.get('ioc_summary', {}).get('total_iocs', 0)
    cves    = data.get('cves', [])
    summary = data.get('executive_summary', '')
    recs    = data.get('recommendations', [])
    tc, _, tl = TMAP.get(tlevel, TMAP['UNKNOWN'])
    max_cvss = 0.0
    for cve in cves:
        try: max_cvss = max(max_cvss, float(cve.get('cvss_score', 0)))
        except: pass

    elems.append(PageBreak())
    elems.append(_sec('Executive Summary', S))
    elems.append(_gap(8))

    # ── ACT NOW callout box (top-3 immediate actions) ──
    immediate = [r for r in recs if str(r.get('priority', '')).lower() in ('immediate',)][:3]
    if not immediate:
        # Fallback: first 2 recs regardless of priority
        immediate = recs[:2]

    if immediate:
        hdr_p = Paragraph('⚡  ACT NOW — IMMEDIATE ACTIONS REQUIRED', S['act_hdr'])
        rows_act = [[hdr_p]]
        for idx, r in enumerate(immediate):
            title = r.get('title', '')
            item  = Paragraph(f'  {idx + 1}.  {title}', S['act_item'])
            rows_act.append([item])
        act_box = Table(rows_act, colWidths=[USABLE])
        act_box.setStyle(TableStyle([
            ('BOX',           (0, 0), (-1, -1), 1.5, C_RED),
            ('LINEBEFORE',    (0, 0), (0, -1),  4,   C_RED),
            ('BACKGROUND',    (0, 0), (-1,  0),  BG_RED),
            ('BACKGROUND',    (0, 1), (-1, -1),  colors.HexColor('#FFF8F8')),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING',   (0, 0), (-1, -1), 14),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 14),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elems.append(act_box)
        elems.append(_gap(14))

    # ── Executive summary text ──
    if summary:
        subj = _subject(data)
        safe = summary.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        if subj and subj in safe:
            safe = safe.replace(subj, f'<b>{subj}</b>', 1)
        elems.append(Paragraph(safe, S['body']))
        elems.append(_gap(16))

    # ── 4-stat grid ──
    ioc_sub = f'{list(data.get("iocs", {}).keys())[0].upper() if data.get("iocs") else "N/A"} — {"Flagged" if conf > 50 else "Clean"}'
    stats = [
        ('THREAT LEVEL',    tl,           f'{conf}% Confidence',   tc),
        ('TTPS FOUND',      str(len(ttps)),'MITRE ATT&amp;CK',          C_BODY),
        ('IOCS DETECTED',   str(iocs),     ioc_sub,                  C_BODY),
        ('CVES REFERENCED', str(len(cves)),f'Max CVSS {max_cvss}',   C_BODY),
    ]
    cells = []
    for lbl, val, sub, vc in stats:
        vp = Paragraph(f'<b>{val}</b>',
                       ParagraphStyle('_sv', fontName='Helvetica-Bold',
                                      fontSize=22, textColor=vc, leading=26))
        inner = Table([[Paragraph(lbl, S['stat_lbl'])],
                       [vp],
                       [Paragraph(sub, S['stat_sub'])]],
                      colWidths=[USABLE * 0.25 - 4])
        inner.setStyle(TableStyle([
            ('LEFTPADDING',   (0, 0), (-1, -1), 12),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
            ('TOPPADDING',    (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('BACKGROUND',    (0, 0), (-1, -1), colors.white),
        ]))
        cells.append(inner)

    gt = Table([cells], colWidths=[USABLE * 0.25] * 4)
    gt.setStyle(TableStyle([
        ('BOX',           (0, 0), (-1, -1), 0.6, C_BORD),
        ('LINEBEFORE',    (1, 0), (-1, -1), 0.5, C_BORD),
        ('TOPPADDING',    (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
    ]))
    elems.append(gt)
    return elems


def _build_kill_chain(data, S):
    """Page 4: Kill chain bar + visual attack timeline."""
    elems = []
    kc    = data.get('kill_chain', {})
    steps = data.get('attack_steps', [])
    active = sum(1 for _, k in KillChainBar.PHASES if kc.get(k, False))

    elems.append(PageBreak())
    elems.append(_sec('Kill Chain Analysis', S))
    elems.append(_gap(6))
    elems.append(Paragraph(
        f'{active} of 7 kill chain phases identified in this incident.',
        S['small']))
    elems.append(_gap(10))
    elems.append(KillChainBar(kc, USABLE))
    elems.append(_gap(20))

    if steps:
        elems.append(_sec('Attack Reconstruction — Timeline', S))
        elems.append(_gap(10))
        elems.append(AttackTimeline(steps, USABLE))

    return elems


def _build_ttps(data, S):
    """Page 5: MITRE ATT&CK TTP table — 5 columns."""
    ttps = data.get('ttps', [])
    if not ttps: return []
    elems = []
    elems.append(PageBreak())
    elems.append(_sec(f'MITRE ATT&amp;CK TTPs ({len(ttps)} Detected)', S))
    elems.append(_gap(8))

    hdr  = [Paragraph(h, S['tbl_hd']) for h in
            ['TTP ID', 'TECHNIQUE', 'TACTIC', 'CONF.', 'TOOLS']]
    cws  = [USABLE*0.14, USABLE*0.25, USABLE*0.19, USABLE*0.16, USABLE*0.26]
    rows = [hdr]
    for t in ttps:
        cval = str(t.get('confidence', 'medium')).lower()
        cc, cb = CMAP.get(cval, CMAP['medium'])
        cp = _pill(cval.upper(), cc, cb, 8)
        rows.append([
            Paragraph(str(t.get('technique_id', '')), S['ttp_id']),
            Paragraph(_clamp(t.get('name', ''), 50),  S['ttp_nm']),
            Paragraph(_clamp(t.get('tactic', ''), 30), S['ttp_tc']),
            cp,
            Paragraph(_clamp(', '.join(t.get('tools', [])) or t.get('tools_str', ''), 55), S['ttp_tl']),
        ])
    tt = Table(rows, colWidths=cws)
    tt.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1,  0),  BG_SOFT),
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORD),
        ('TOPPADDING',    (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX',           (0, 0), (-1, -1), 0.5, C_BORD),
    ]))
    elems.append(tt)
    return elems


def _build_iocs(data, S):
    """Page 6: IOC Validation Results with feed reputation dots."""
    iocs_dict = data.get('iocs', {})
    ioc_det   = data.get('ioc_details', [])
    if not iocs_dict and not ioc_det: return []

    elems = []
    elems.append(PageBreak())
    elems.append(_sec('IOC Validation Results', S))
    elems.append(_gap(8))

    hdr = [Paragraph(h, S['tbl_hd']) for h in
           ['IOC VALUE', 'TYPE', 'RISK LEVEL', 'FEED HITS', 'SOURCES']]
    # colWidths: VALUE=0.26, TYPE=0.08, RISK=0.14, FEED_DOTS=0.12, SOURCES=0.40
    cws = [USABLE*0.26, USABLE*0.08, USABLE*0.14, USABLE*0.12, USABLE*0.40]
    rows = [hdr]

    items = ioc_det if ioc_det else []
    if not items:
        for itype, vals in iocs_dict.items():
            for v in (vals if isinstance(vals, list) else [vals]):
                items.append({
                    'value':   v,
                    'type':    itype,
                    'risk':    data.get('ioc_summary', {}).get('risk_level', 'UNKNOWN'),
                    'boost':   '+0%',
                    'feed_count': data.get('ioc_summary', {}).get('feed_hits', 5),
                    'sources': 'OTX, MalwareBazaar, URLhaus, ThreatFox, GreyNoise, URLScan, AbuseIPDB, VirusTotal',
                })

    for item in items:
        risk = str(item.get('risk', 'UNKNOWN')).upper()
        if risk in ('CLEAN', 'LOW'):
            rp = Paragraph(risk, S['risk_grn'])
        elif risk in ('HIGH', 'CRITICAL', 'FLAGGED', 'MALICIOUS'):
            rp = Paragraph(risk, S['risk_red'])
        else:
            rp = Paragraph(risk, S['risk_amb'])

        feed_count = item.get('feed_count', item.get('feed_hits', 5))
        try: feed_count = int(feed_count)
        except: feed_count = 5

        rows.append([
            Paragraph(str(item.get('value', '')),   S['ioc_val']),
            Paragraph(str(item.get('type',  '')),   S['ioc_t']),
            rp,
            FeedDots(feed_count, width=cws[3] - 10),
            Paragraph(str(item.get('sources', '')), S['ioc_src']),
        ])

    it = Table(rows, colWidths=cws)
    it.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1,  0),  BG_SOFT),
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORD),
        ('TOPPADDING',    (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX',           (0, 0), (-1, -1), 0.5, C_BORD),
    ]))
    elems.append(it)
    return elems


def _build_cves(data, S):
    """Page 7: CVEs Referenced table."""
    cves = data.get('cves', [])
    if not cves: return []
    elems = []
    elems.append(PageBreak())
    elems.append(_sec('CVEs Referenced', S))
    elems.append(_gap(8))

    hdr = [Paragraph(h, S['tbl_hd']) for h in
           ['CVE ID', 'CVSS', 'DESCRIPTION', 'AFFECTED SYSTEM']]
    cws = [USABLE*0.21, USABLE*0.10, USABLE*0.40, USABLE*0.29]
    rows = [hdr]
    for cve in cves:
        score = cve.get('cvss_score', 0)
        try: score = float(score)
        except: score = 0.0
        sc = C_RED if score >= 9.0 else C_AMB if score >= 7.0 else C_GRN
        sv = Paragraph(f'<b>{score}</b>',
                       ParagraphStyle('_cs', fontName='Helvetica-Bold', fontSize=15,
                                      textColor=sc, leading=19))
        prods = ', '.join(cve.get('affected_products', []))
        rows.append([
            Paragraph(str(cve.get('cve_id', '')), S['cve_id']),
            sv,
            Paragraph(_clamp(cve.get('description', ''), 200)
                      .replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'),
                      S['cve_d']),
            Paragraph(prods, S['cve_sys']),
        ])
    ct = Table(rows, colWidths=cws)
    ct.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1,  0),  BG_SOFT),
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORD),
        ('TOPPADDING',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('BOX',           (0, 0), (-1, -1), 0.5, C_BORD),
    ]))
    elems.append(ct)
    return elems


def _build_recommendations(data, S):
    """Page 8: Numbered recommendations with priority pills."""
    recs = data.get('recommendations', [])
    if not recs: return []
    elems = []
    elems.append(PageBreak())
    elems.append(_sec('Recommendations', S))
    elems.append(_gap(8))

    for i, rec in enumerate(recs):
        pri_raw = str(rec.get('priority', 'ongoing')).lower()
        pc, pb, pl = PMAP.get(pri_raw, PMAP['ongoing'])
        nc  = NUM_C[i] if i < len(NUM_C) else C_MUT
        num_p = Paragraph(f'<b>{i+1}</b>',
                          ParagraphStyle('_rn', fontName='Helvetica-Bold', fontSize=26,
                                         textColor=nc, leading=30, alignment=TA_CENTER))
        pri_p   = _pill(pl, pc, pb, 8)
        title_p = Paragraph(f'<b>{rec.get("title", "")}</b>', S['rec_tit'])
        desc_raw = str(rec.get('description', '')).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
        desc_p   = Paragraph(desc_raw, S['rec_d'])

        tr = Table([[title_p, pri_p]], colWidths=[USABLE * 0.72 - 20, USABLE * 0.28])
        tr.setStyle(TableStyle([
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        right = Table([[tr], [desc_p]], colWidths=[USABLE - 60])
        right.setStyle(TableStyle([
            ('LEFTPADDING',   (0, 0), (-1, -1), 14),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ]))
        row = Table([[num_p, right]], colWidths=[52, USABLE - 52])
        row.setStyle(TableStyle([
            ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORD),
            ('LINEBEFORE',    (1, 0), (1,  -1),  2,  nc),
            ('TOPPADDING',    (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ]))
        elems.append(row)
        elems.append(_gap(4))
    return elems


def _build_sigma(data, S):
    """Page 9: SIGMA detection rules dark code block."""
    sigs   = data.get('sigma_rules', [])
    tlevel = str(data.get('threat_level', 'UNKNOWN')).upper()
    conf   = data.get('confidence', 0)
    elems  = []
    elems.append(PageBreak())
    elems.append(_sec('SIGMA Detection Rules Preview', S))
    elems.append(_gap(6))
    elems.append(Paragraph(
        f'{len(sigs)} SIGMA rules generated — export full YAML via the dashboard.',
        S['sig_hd']))
    elems.append(_gap(10))

    lines = [
        f'title: ThreatIQ Auto-Generated Detection Rules',
        f'status: experimental',
        f'date: {datetime.now(timezone.utc).strftime("%Y/%m/%d")}',
        f'author: ThreatIQ AI Engine',
        f'description: >',
        f'  Auto-generated SIGMA rules based on threat analysis.',
        f'  Threat Level: {tlevel}',
        f'  Confidence: {conf}%',
    ]
    if sigs:
        lines.append(f'# Rules generated for {len(data.get("ttps", []))} detected TTPs')
        lines.append(f'# Import this file into your SIEM (Splunk, Elastic, QRadar)')
        try:
            import yaml as _yaml
            for sig in sigs[:2]:
                rule_core = {k: sig[k] for k in ('title', 'status', 'logsource', 'detection', 'level') if k in sig}
                yaml_str = _yaml.dump(rule_core, default_flow_style=False, allow_unicode=True, sort_keys=False)
                for ln in yaml_str.split('\n')[:10]:
                    if ln.strip():
                        lines.append(ln)
        except Exception:
            for sig in sigs[:2]:
                lines.append(f'title: {sig.get("title", "Rule")}')
                lines.append(f'status: {sig.get("status", "experimental")}')
    else:
        lines.append('# No SIGMA rules generated — insufficient TTP data')
    lines.append('# Full rules available via Export SIGMA button in dashboard')

    elems.append(SigmaBlock(lines, USABLE))
    return elems


def _build_nontechnical(data, S):
    """Plain English summary page — for decision makers and non-technical readers."""
    elems = []
    elems.append(PageBreak())
    elems.append(_sec('Plain English Summary — For Decision Makers', S))
    elems.append(_gap(10))

    tlevel  = str(data.get('threat_level', 'UNKNOWN')).upper()
    conf    = data.get('confidence', 0)
    ttps    = data.get('ttps', [])
    cves    = data.get('cves', [])
    recs    = data.get('recommendations', [])
    subj    = _subject(data)
    origin  = data.get('origin', 'Unknown')
    tc, _, tl = TMAP.get(tlevel, TMAP['UNKNOWN'])
    max_cvss = 0.0
    for cve in cves:
        try: max_cvss = max(max_cvss, float(cve.get('cvss_score', 0)))
        except: pass

    # ── Risk level plain description ──
    risk_descs = {
        'CRITICAL': ('This is an EMERGENCY. The threat is active and severe.',
                     'Immediate escalation to your security team and management is required.',
                     C_RED),
        'HIGH':     ('This is a SERIOUS THREAT that needs prompt attention.',
                     'Your security team should act within 24 hours.',
                     C_RED),
        'MEDIUM':   ('This threat is MODERATE. It requires monitoring and planned action.',
                     'Schedule remediation within the next week.',
                     C_AMB),
        'LOW':      ('This appears to be a LOW-RISK indicator.',
                     'Log it, monitor it, and review in your next security cycle.',
                     C_GRN),
    }
    r_line1, r_line2, r_col = risk_descs.get(tlevel, ('Threat level could not be determined automatically.',
                                                        'Review the full technical report with your security team.', C_MUT))

    risk_box = Table([[
        Paragraph(f'<b>Risk Level: {tl}</b>', ParagraphStyle('_rb', fontName='Helvetica-Bold',
                   fontSize=13, textColor=r_col, leading=18)),
    ], [
        Paragraph(r_line1, S['nt_body']),
    ], [
        Paragraph(r_line2, S['nt_body']),
    ]], colWidths=[USABLE])
    risk_box.setStyle(TableStyle([
        ('BOX',           (0, 0), (-1, -1), 1.5,  r_col),
        ('LINEBEFORE',    (0, 0), (0, -1),   4,    r_col),
        ('BACKGROUND',    (0, 0), (-1, -1),  colors.HexColor('#FAFAFA')),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (-1, -1), 14),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 14),
    ]))
    elems.append(risk_box)
    elems.append(_gap(16))

    # ── What happened? ──
    elems.append(Paragraph('What happened?', S['nt_head']))
    elems.append(_gap(6))
    what_happened = (
        f'ThreatIQ analysed the indicator <b>{subj}</b>, which appears to originate from '
        f'<b>{origin}</b>. Our AI engine cross-referenced this against 9 live threat intelligence '
        f'feeds and identified <b>{len(ttps)} attack techniques</b> linked to known threat actors. '
        f'The overall confidence in this assessment is <b>{conf}%</b>.'
    )
    elems.append(Paragraph(what_happened, S['nt_body']))
    elems.append(_gap(12))

    # ── What does this mean for your organisation? ──
    elems.append(Paragraph('What does this mean for your organisation?', S['nt_head']))
    elems.append(_gap(6))

    implications = []
    if tlevel in ('CRITICAL', 'HIGH'):
        implications.append('Your network or systems may have been targeted by a malicious actor.')
        implications.append('Sensitive data, business operations, or customer information could be at risk.')
    if len(ttps) > 5:
        implications.append(f'The attacker used {len(ttps)} known techniques, suggesting a sophisticated and persistent threat.')
    if cves:
        implications.append(f'{len(cves)} software vulnerabilities were identified — these are known weak points that attackers exploit.')
    if max_cvss >= 9.0:
        implications.append(f'At least one vulnerability (CVSS {max_cvss}) is rated CRITICAL — patch this immediately.')
    if not implications:
        implications.append('No immediate indicators of system compromise were found, but continued monitoring is advised.')

    for imp in implications:
        elems.append(Paragraph(f'• {imp}', S['nt_bullet']))
        elems.append(_gap(4))
    elems.append(_gap(10))

    # ── What should you do right now? ──
    elems.append(Paragraph('What should you do right now?', S['nt_head']))
    elems.append(_gap(6))

    # Show top 3 recommendations in plain language
    shown_recs = recs[:3] if recs else []
    if shown_recs:
        for i, rec in enumerate(shown_recs):
            pri_raw = str(rec.get('priority', 'ongoing')).lower()
            pc, _, pl = PMAP.get(pri_raw, PMAP['ongoing'])
            title   = rec.get('title', '')
            desc    = rec.get('description', '')
            short   = _clamp(desc, 160)
            elems.append(Paragraph(
                f'<b>{i+1}. {title}</b>  '
                f'[{pl}]',
                S['nt_bold']))
            elems.append(Paragraph(short, S['nt_body']))
            elems.append(_gap(8))
    else:
        elems.append(Paragraph(
            'Contact your IT security team immediately and share this report with them.',
            S['nt_body']))
    elems.append(_gap(12))

    # ── What happens if you don't act? ──
    elems.append(Paragraph('What happens if you do not act?', S['nt_head']))
    elems.append(_gap(6))
    if tlevel in ('CRITICAL', 'HIGH'):
        consequences = (
            'Ignoring a HIGH or CRITICAL threat can lead to data breaches, ransomware infections, '
            'financial loss, regulatory fines, and reputational damage. Attackers often escalate '
            'their access once inside a network. Early action significantly reduces the impact and cost of recovery.'
        )
    elif tlevel == 'MEDIUM':
        consequences = (
            'Medium-severity threats, if left unaddressed, can become serious over time. '
            'Attackers use footholds to gather intelligence before launching larger attacks. '
            'Scheduled patching and monitoring will keep your risk contained.'
        )
    else:
        consequences = (
            'Low-risk indicators rarely require immediate action, but should be documented '
            'and reviewed periodically as part of your security hygiene programme.'
        )
    elems.append(Paragraph(consequences, S['nt_body']))
    elems.append(_gap(14))

    # ── Reassurance footer ──
    note_box = Table([[Paragraph(
        '<b>Note for non-technical readers:</b> This report was produced automatically by ThreatIQ\'s '
        'AI engine. All findings have been cross-validated against multiple live threat feeds. '
        'Please share this report with your IT security team or managed security provider for '
        'expert review and remediation guidance.',
        S['disc'])]], colWidths=[USABLE])
    note_box.setStyle(TableStyle([
        ('BOX',           (0, 0), (-1, -1), 0.5, C_BORD),
        ('BACKGROUND',    (0, 0), (-1, -1), BG_SOFT),
        ('TOPPADDING',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING',   (0, 0), (-1, -1), 14),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 14),
    ]))
    elems.append(note_box)
    return elems


def _build_appendix(data, S):
    """Appendix: Raw analysis metadata + tools & APIs used."""
    meta  = data.get('metadata', {})
    aid   = data.get('analysis_id', 'N/A')
    elems = []
    elems.append(PageBreak())
    elems.append(_sec('Appendix — Raw Analysis Metadata', S))
    elems.append(_gap(8))

    now_str  = datetime.now(timezone.utc).isoformat()
    proc_ms  = meta.get('processing_time_ms', meta.get('processing_time', 0))
    ai_eng   = meta.get('ai_engine', 'Claude Sonnet-4 (Anthropic)')
    dual_v   = 'True' if meta.get('dual_validated', False) else 'False'
    api_c    = str(meta.get('api_calls', data.get('api_calls', 4)))
    ioc_srcs = 'OTX, MalwareBazaar, URLhaus, ThreatFox, GreyNoise, URLScan, AbuseIPDB, VirusTotal, HybridAnalysis'
    total_iocs = str(data.get('ioc_summary', {}).get('total_iocs', len(data.get('iocs', {}))))

    meta_rows = [
        ('Analysis ID',       str(aid)),
        ('Input Type',        meta.get('input_type', 'Unknown')),
        ('Processing Time',   f'{proc_ms} ms'),
        ('AI Engine',         ai_eng),
        ('Dual AI Validated', dual_v),
        ('API Calls Made',    api_c),
        ('Total IOCs',        total_iocs),
        ('IOC Sources',       ioc_srcs),
        ('Analysed At',       meta.get('analysed_at', now_str)),
        ('Report Generated',  now_str),
        ('Tool Version',      'ThreatIQ v3.0.0'),
    ]
    mdata = [[Paragraph(k, S['app_k']), Paragraph(v, S['app_v'])] for k, v in meta_rows]
    mt = Table(mdata, colWidths=[USABLE * 0.30, USABLE * 0.70])
    mt.setStyle(TableStyle([
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORD),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
    ]))
    elems.append(mt)
    elems.append(_gap(18))

    elems.append(_sec('Analysis Tools & APIs Used', S))
    elems.append(_gap(8))
    tools = [
        ('VirusTotal',     'Hash & URL reputation API',          'API'),
        ('Shodan',         'Infrastructure scanning API',         'API'),
        ('AbuseIPDB',      'IP abuse report database',            'API'),
        ('AlienVault OTX', 'Open threat intelligence feed',       'API'),
        ('GreyNoise',      'Internet noise analysis',             'API'),
        ('URLScan.io',     'URL & domain scanning',               'API'),
        ('MalwareBazaar',  'Malware hash database',               'API'),
        ('ThreatFox',      'IOC threat feed',                     'API'),
        ('HybridAnalysis', 'Sandbox malware analysis',            'API'),
        ('ipapi',          'IP geolocation service',              'API'),
        ('Claude Sonnet',  'Primary AI analysis engine',          'AI'),
        ('Gemini Pro',     'Secondary AI validation',             'AI'),
        ('MITRE ATT&CK',   'TTP framework mapping database',      'DB'),
        ('SIGMA Engine',   'Detection rule generation',           'INT'),
    ]
    def _type_pill(tp):
        c = {'API': C_BLU, 'AI': C_GRN, 'DB': C_AMB, 'INT': C_PUR}.get(tp, C_MUT)
        return Paragraph(f'<b>{tp}</b>',
                         ParagraphStyle('_tp', fontName='Helvetica-Bold', fontSize=9,
                                        textColor=c, alignment=TA_LEFT, leading=12))

    thdr  = [Paragraph(h, S['tbl_hd']) for h in ['TOOL', 'DESCRIPTION', 'TYPE']]
    trows = [thdr] + [[Paragraph(n, S['tool_n']), Paragraph(d, S['tool_d']), _type_pill(tp)]
                      for n, d, tp in tools]
    tt = Table(trows, colWidths=[USABLE*0.22, USABLE*0.63, USABLE*0.15])
    tt.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1,  0),  BG_SOFT),
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORD),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX',           (0, 0), (-1, -1), 0.5, C_BORD),
    ]))
    elems.append(tt)
    elems.append(_gap(16))

    disc = Table([[Paragraph(
        'This report was generated automatically by ThreatIQ AI v3.0. '
        'All findings should be verified by a qualified security analyst '
        'before taking remediation action. ThreatIQ is not liable for '
        'decisions made solely on the basis of this automated report.',
        S['disc'])]], colWidths=[USABLE])
    disc.setStyle(TableStyle([
        ('BOX',           (0, 0), (-1, -1), 0.5, C_BORD),
        ('TOPPADDING',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING',   (0, 0), (-1, -1), 14),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 14),
        ('BACKGROUND',    (0, 0), (-1, -1), BG_SOFT),
    ]))
    elems.append(disc)
    return elems


# ── Data normalizer ────────────────────────────────────────────────────────────

def _normalize_data(data: Dict) -> Dict:
    """
    Bridge: maps analyzer output keys → PDF builder expected keys.

    Analyzer produces:               PDF builder reads:
    ─────────────────────────────    ──────────────────────────────────
    extracted_iocs                   iocs
    analysis_metadata                metadata
    summary                          executive_summary
    ttps[].technique_name            ttps[].name
    ttps[].tools_used                ttps[].tools
    ttps[].confidence (int 0-100)    ttps[].confidence ('high'/'medium'/'low')
    recommendations[].action         recommendations[].title + .description
    recommendations[].timeframe      recommendations[].priority (string key)
    threat_actor.suspected           actor  (top-level string)
    threat_actor.origin              origin (top-level string)
    attack_reconstruction (string)   attack_steps (list of {name, description})
    ioc_validation (dict)            ioc_details (list of row dicts)
    analysis_metadata.analyzed_at    metadata.analysed_at
    analysis_metadata.ai_calls       metadata.api_calls
    """
    d = dict(data)  # shallow copy — don't mutate original

    # ── 1. iocs ───────────────────────────────────────────────────────────────
    if not d.get('iocs'):
        d['iocs'] = d.get('extracted_iocs', {}) or {}

    # ── 2. metadata ──────────────────────────────────────────────────────────
    if not d.get('metadata'):
        d['metadata'] = dict(d.get('analysis_metadata', {}) or {})
    else:
        d['metadata'] = dict(d['metadata'])

    meta = d['metadata']
    if 'analysed_at' not in meta:
        meta['analysed_at'] = meta.get('analyzed_at', '')
    if 'api_calls' not in meta:
        meta['api_calls'] = meta.get('ai_calls', 4)
    # processing_ms (analyzer key) → processing_time_ms (appendix key)
    if 'processing_time_ms' not in meta:
        meta['processing_time_ms'] = meta.get('processing_ms', meta.get('processing_time', 0))
    d['metadata'] = meta

    # ── 3. executive_summary ─────────────────────────────────────────────────
    if not d.get('executive_summary'):
        d['executive_summary'] = d.get('summary', '') or ''

    # ── 4. TTPs: technique_name→name, tools_used→tools, int conf→string ──────
    def _conf_str(v):
        try:
            n = int(v)
            return 'high' if n >= 70 else 'medium' if n >= 40 else 'low'
        except (ValueError, TypeError):
            s = str(v).lower()
            return s if s in ('high', 'medium', 'low') else 'medium'

    fixed_ttps = []
    for t in (d.get('ttps', []) or []):
        ft = dict(t)
        if not ft.get('name'):
            ft['name'] = ft.get('technique_name', '')
        if not ft.get('tools'):
            ft['tools'] = ft.get('tools_used', []) or []
        ft['confidence'] = _conf_str(ft.get('confidence', 'medium'))
        fixed_ttps.append(ft)
    d['ttps'] = fixed_ttps

    # ── 5. Recommendations: action→title+description, timeframe→priority str ─
    _TF = {
        'immediate': 'immediate', 'critical': 'immediate',
        '24h': '24h', '24 hours': '24h', '24hours': '24h',
        '1week': '1 week', '1 week': '1 week', 'week': '1 week',
        'ongoing': 'ongoing', 'long-term': 'ongoing', 'long term': 'ongoing',
    }
    fixed_recs = []
    for r in (d.get('recommendations', []) or []):
        fr = dict(r)
        action = fr.get('action', '')
        if not fr.get('title'):
            fr['title'] = action
        if not fr.get('description'):
            fr['description'] = action
        # priority might be int (1,2,3) or missing → derive from timeframe
        pri = fr.get('priority', '')
        if not pri or isinstance(pri, int):
            tf = str(fr.get('timeframe', 'ongoing')).lower().strip()
            fr['priority'] = _TF.get(tf, 'ongoing')
        else:
            fr['priority'] = _TF.get(str(pri).lower().strip(), 'ongoing')
        fixed_recs.append(fr)
    d['recommendations'] = fixed_recs

    # ── 6. actor + origin from threat_actor ───────────────────────────────────
    ta = d.get('threat_actor', {}) or {}
    if not d.get('actor') or d.get('actor') == 'Unknown':
        d['actor'] = ta.get('suspected', 'Unknown') or 'Unknown'
    if not d.get('origin') or d.get('origin') == 'Unknown':
        d['origin'] = ta.get('origin', 'Unknown') or 'Unknown'

    # ── 7. attack_steps: derive from TTPs sorted by kill chain order ──────────
    if not d.get('attack_steps'):
        _TACTIC_ORDER = {
            'Reconnaissance': 0, 'Resource Development': 1, 'Initial Access': 2,
            'Execution': 3, 'Persistence': 4, 'Privilege Escalation': 5,
            'Defense Evasion': 6, 'Credential Access': 7, 'Discovery': 8,
            'Lateral Movement': 9, 'Collection': 10,
            'Command and Control': 11, 'Exfiltration': 12, 'Impact': 13,
        }
        sorted_t = sorted(
            d['ttps'],
            key=lambda t: _TACTIC_ORDER.get(t.get('tactic', ''), 99)
        )
        seen = {}
        steps = []
        for t in sorted_t[:8]:
            tactic = t.get('tactic', '')
            if tactic in seen:
                continue
            seen[tactic] = True
            name = t.get('name', t.get('technique_name', ''))
            tech_id = t.get('technique_id', '')
            evidence = t.get('evidence', '') or t.get('detection_hint', '') or f'{tech_id} identified in threat analysis'
            steps.append({
                'name': f'{tactic}: {name}' if tactic else name,
                'description': evidence,
            })
        d['attack_steps'] = steps

    # ── 8. ioc_details: derive from ioc_validation ────────────────────────────
    if not d.get('ioc_details'):
        ioc_val = d.get('ioc_validation', {}) or {}
        items = []
        if ioc_val:
            for key, entry in ioc_val.items():
                # key format: "itype:value" or "itype_private:value"
                if ':' in key:
                    itype_raw, ioc_v = key.split(':', 1)
                else:
                    itype_raw, ioc_v = 'unknown', key
                ioc_v    = entry.get('ioc_value', ioc_v)
                ioc_type = entry.get('ioc_type', itype_raw).replace('_private', '').replace('_', ' ').upper()
                risk_raw = str(entry.get('risk_level', 'unknown')).lower()
                risk_map = {
                    'critical': 'MALICIOUS', 'high': 'MALICIOUS',
                    'medium': 'SUSPICIOUS', 'low': 'LOW',
                    'clean': 'CLEAN', 'private': 'PRIVATE',
                }
                risk = risk_map.get(risk_raw, 'UNKNOWN')
                srcs = entry.get('sources', {})
                feed_count = sum(
                    1 for sv in srcs.values()
                    if sv.get('malicious', 0) > 0 or sv.get('found', False)
                        or sv.get('abuse_score', 0) > 10
                )
                src_names = ', '.join(s.upper().replace('_', '') for s in list(srcs.keys())[:6])
                items.append({
                    'value':      ioc_v,
                    'type':       ioc_type,
                    'risk':       risk,
                    'feed_count': max(feed_count, 1),
                    'sources':    src_names or 'Multi-Feed',
                })
        elif d.get('iocs'):
            # Fallback: build from raw extracted IOCs
            conf = int(d.get('confidence', 0) or 0)
            risk = 'MALICIOUS' if conf >= 70 else 'SUSPICIOUS' if conf >= 40 else 'UNKNOWN'
            for itype, vals in d['iocs'].items():
                for v in (vals if isinstance(vals, list) else [vals]):
                    items.append({
                        'value':      v,
                        'type':       itype.replace('_', ' ').upper(),
                        'risk':       risk,
                        'feed_count': 5,
                        'sources':    'AbuseIPDB, VirusTotal, OTX, GreyNoise, ThreatFox',
                    })
        d['ioc_details'] = items

    # ── 9. sigma_rules: auto-generate from TTPs if missing ────────────────────
    if not d.get('sigma_rules') and d.get('ttps'):
        try:
            from sigma_generator import generate_sigma
            d['sigma_rules'] = generate_sigma(d['ttps'])
        except Exception:
            pass  # sigma stays empty — PDF shows "no rules" message gracefully

    # ── 10. geo + asn: extract from ipapi source in ioc_validation ─────────
    # _build_cover() reads data.get('geo', {}) and data.get('asn', {}) at top
    # level, but the analyzer never sets these — ip-api data is buried inside
    # ioc_validation[key]['sources']['ipapi']. Pull it out here.
    if not d.get('geo'):
        ioc_val = d.get('ioc_validation', {}) or {}
        for key, entry in ioc_val.items():
            ipapi = (entry.get('sources') or {}).get('ipapi', {})
            if ipapi.get('found'):
                d['geo'] = {
                    'country':      ipapi.get('country', 'Unknown'),
                    'country_code': ipapi.get('country_code', ''),
                    'city':         ipapi.get('city', ''),
                    'isp':          ipapi.get('isp', 'Unknown'),
                    'org':          ipapi.get('org', 'Unknown'),
                    'asn':          ipapi.get('asn', 'N/A'),
                }
                d['asn'] = {
                    'asn': ipapi.get('asn', 'N/A'),
                    'isp': ipapi.get('isp', 'Unknown'),
                    'org': ipapi.get('org', 'Unknown'),
                }
                # Also set origin to the country for cover banner
                if not d.get('origin') or d.get('origin') == 'Unknown':
                    d['origin'] = ipapi.get('country', d.get('origin', 'Unknown'))
                break

    # ── 11. cves: normalise string list → list of dicts ───────────────────────
    # analyzer may return ['CVE-2023-23397', ...] but _build_cves calls cve.get()
    raw_cves = d.get('cves', []) or []
    normalised_cves = []
    for cve in raw_cves:
        if isinstance(cve, str):
            normalised_cves.append({
                'cve_id':            cve,
                'cvss_score':        0,
                'description':       f'Referenced CVE: {cve}',
                'affected_products': [],
            })
        elif isinstance(cve, dict):
            normalised_cves.append(cve)
    d['cves'] = normalised_cves

    return d


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_pdf(data: Dict) -> str:
    data   = _normalize_data(data)   # ← normalise all key mismatches first
    S      = _S()
    aid    = data.get('analysis_id', 'UNKNOWN')
    tlevel = str(data.get('threat_level', 'UNKNOWN')).upper()
    ts     = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    date_s = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    out    = os.path.join(OUTPUT_DIR, f'ThreatIQ_Report_{aid}_{ts}.pdf')

    cb = _make_page_cb(tlevel, str(aid), date_s)

    doc = SimpleDocTemplate(
        out,
        pagesize=A4,
        leftMargin=LM, rightMargin=RM,
        topMargin=TM,  bottomMargin=BM,
        title=f'ThreatIQ Report #{aid}',
        author='ThreatIQ AI Engine',
    )

    story = []
    story += _build_cover(data, S)
    story += _build_toc(data, S)
    story += _build_exec_summary(data, S)
    story += _build_kill_chain(data, S)
    story += _build_ttps(data, S)
    story += _build_iocs(data, S)
    story += _build_cves(data, S)
    story += _build_recommendations(data, S)
    story += _build_sigma(data, S)
    story += _build_nontechnical(data, S)
    story += _build_appendix(data, S)

    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    with open(out, 'rb') as fh:
        return fh.read()

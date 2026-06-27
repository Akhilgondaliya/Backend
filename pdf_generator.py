import io
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
import tldextract

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute total page count and draw
    matching header lines, disclaimers, and page counters.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        
        # Skip drawing decorations on the cover page (Page 1)
        if self._pageNumber == 1:
            self.restoreState()
            return
            
        # Elegant, thin geometric page frame border
        self.setStrokeColor(colors.HexColor('#e2e8f0'))
        self.setLineWidth(0.75)
        self.rect(36, 36, 612 - 72, 792 - 72)
        
        # Bottom Rule above footer text
        self.setStrokeColor(colors.HexColor('#cbd5e1'))
        self.setLineWidth(0.5)
        self.line(54, 56, 612 - 54, 56)
        
        # Footer Disclaimer & Page Counters
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor('#94a3b8'))
        self.drawString(54, 42, "Disclaimer: Developed as a hands-on cybersecurity research project.")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 42, page_text)
        
        self.restoreState()


def resolve_logo_source(logo_source):
    if isinstance(logo_source, str) and logo_source:
        if not os.path.isabs(logo_source):
            logo_source = os.path.join(os.path.dirname(__file__), logo_source)
        if os.path.exists(logo_source):
            return logo_source
    return logo_source


def add_cover_page(story, scan_data, title_text, logo_source):
    logo_source = resolve_logo_source(logo_source)
    verdict_text = scan_data.get('verdict', 'Safe').upper()
    score = scan_data.get('score', 0)

    cover_title_style = ParagraphStyle(
        'CoverTitle',
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=34,
        textColor=colors.HexColor('#0f172a'),
        alignment=0,
        spaceAfter=15
    )
    
    cover_subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#475569'),
        alignment=0,
        spaceAfter=20
    )
    
    cover_meta_label = ParagraphStyle(
        'CoverMetaLabel',
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#94a3b8'),
        spaceAfter=3
    )
    
    cover_meta_val = ParagraphStyle(
        'CoverMetaVal',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=10
    )

    confidential_style = ParagraphStyle(
        'CoverConfidential',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#94a3b8'),
        alignment=0
    )

    target_type = "File Binary Sandbox" if 'filetype' in scan_data else ("Email Spoof Analysis" if 'sender_analysis' in scan_data else "Website URL Scan")
    target_val = scan_data.get('filename', 'Unknown File') if 'filetype' in scan_data else (scan_data.get('sender_analysis', {}).get('email', 'Unknown Email') if 'sender_analysis' in scan_data else scan_data.get('url', 'N/A'))
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_ref = datetime.now().strftime('PHZ-%Y%m%d-%H%M%S')

    # 1. Add logo
    if logo_source and ((isinstance(logo_source, str) and os.path.exists(logo_source)) or not isinstance(logo_source, str)):
        try:
            logo_img = Image(logo_source, width=140, height=32)
            logo_img.hAlign = 'LEFT'
            story.append(logo_img)
        except Exception:
            logo_img = None
    else:
        logo_img = None

    if not logo_img:
        fallback_style = ParagraphStyle('CoverFallbackLogo', fontName='Helvetica-Bold', fontSize=20, textColor=colors.HexColor('#0f172a'), alignment=0)
        story.append(Paragraph('Phish<b>Zero</b> Security Sandbox', fallback_style))

    story.append(Spacer(1, 28))

    accent_bar = Table([['']], colWidths=[504], rowHeights=[6])
    accent_bar.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0ea5e9')),
        ('PADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(accent_bar)
    story.append(Spacer(1, 22))

    story.append(Paragraph(title_text, cover_title_style))
    story.append(Paragraph('Security Threat Intelligence Report for enterprise phishing protection and incident response teams.', cover_subtitle_style))
    story.append(Spacer(1, 16))

    meta_rows = [
        [Paragraph('AUDIT TARGET TYPE', cover_meta_label), Paragraph('SCAN DATE / TIMESTAMP', cover_meta_label)],
        [Paragraph(target_type, cover_meta_val), Paragraph(date_str, cover_meta_val)],
        [Paragraph('CONFIDENCE LEVEL', cover_meta_label), Paragraph('REPORT REFERENCE', cover_meta_label)],
        [Paragraph(f"{scan_data.get('confidence', 95)}%", cover_meta_val), Paragraph(report_ref, cover_meta_val)]
    ]

    meta_table = Table(meta_rows, colWidths=[252, 252])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 22))

    verdict_desc_style = ParagraphStyle(
        'CoverVerdictDesc',
        fontName='Helvetica-Oblique',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
    )

    if verdict_text == 'PHISHING':
        verdict_color = colors.HexColor('#991b1b')
        verdict_desc = 'DANGER: High phishing indicators, malicious heuristics, or active domain threat blocks triggered.'
    elif verdict_text == 'SUSPICIOUS':
        verdict_color = colors.HexColor('#c2410c')
        verdict_desc = 'WARNING: Suspicious parameters detected. Caution recommended before interaction.'
    else:
        verdict_color = colors.HexColor('#065f46')
        verdict_desc = 'SAFE: No critical threat signatures or fraudulent keywords found.'

    verdict_badge_style = ParagraphStyle(
        'CoverVerdictBadge',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.white,
        alignment=1
    )
    verdict_badge_text = Paragraph(f"VERDICT: {verdict_text} (Score: {score}/100)", verdict_badge_style)
    verdict_badge_tbl = Table([[verdict_badge_text]], colWidths=[280], rowHeights=[24])
    verdict_badge_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('PADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(verdict_badge_tbl)
    story.append(Spacer(1, 10))
    story.append(Paragraph(verdict_desc, verdict_desc_style))
    story.append(Spacer(1, 40))
    story.append(Paragraph('PhishZero delivers pro-active threat scoring, URL behavioral context, and forensic guidance for cyber defenders.', confidential_style))
    story.append(PageBreak())
        verdict_color = colors.HexColor('#991b1b')
        verdict_desc = "DANGER: High phishing indicators, malicious heuristics, or active domain threat blocks triggered."
    elif verdict_text == 'SUSPICIOUS':
        verdict_color = colors.HexColor('#c2410c')
        verdict_desc = "WARNING: Suspicious parameters detected. Caution recommended before interaction."
    else:
        verdict_color = colors.HexColor('#065f46')
        verdict_desc = "SAFE: No critical threat signatures or fraudulent keywords found."
        
    verdict_badge_style = ParagraphStyle(
        'CoverVerdictBadge',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.white,
        alignment=1
    )
    verdict_badge_text = Paragraph(f"VERDICT: {verdict_text} (Score: {score}/100)", verdict_badge_style)
    verdict_badge_tbl = Table([[verdict_badge_text]], colWidths=[280], rowHeights=[24])
    verdict_badge_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('PADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(verdict_badge_tbl)
    story.append(Spacer(1, 10))
    
    verdict_desc_style = ParagraphStyle(
        'CoverVerdictDesc',
        fontName='Helvetica-Oblique',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
    )
    story.append(Paragraph(verdict_desc, verdict_desc_style))
    
    story.append(Spacer(1, 80))
    
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    target_type = "File Binary Sandbox" if 'filetype' in scan_data else ("Email Spoof Analysis" if 'sender_analysis' in scan_data else "Website URL Scan")
    target_val = scan_data.get('filename', 'Unknown File') if 'filetype' in scan_data else (scan_data.get('sender_analysis', {}).get('email', 'Unknown Email') if 'sender_analysis' in scan_data else scan_data.get('url', 'N/A'))
    
    meta_rows = [
        [
            Paragraph("AUDIT TARGET TYPE", cover_meta_label),
            Paragraph("SCAN DATE / TIMESTAMP", cover_meta_label)
        ],
        [
            Paragraph(target_type, cover_meta_val),
            Paragraph(date_str, cover_meta_val)
        ],
        [
            Paragraph("TARGET SIGNATURE", cover_meta_label),
            Paragraph("CONFIDENCE LEVEL", cover_meta_label)
        ],
        [
            Paragraph(f"<font face='Courier-Bold' size='9'>{target_val}</font>", cover_meta_val),
            Paragraph(f"{scan_data.get('confidence', 95)}%", cover_meta_val)
        ]
    ]
    
    meta_table = Table(meta_rows, colWidths=[252, 252])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    
    story.append(Spacer(1, 40))
    
    confidential_style = ParagraphStyle(
        'CoverConfidential',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#94a3b8'),
        alignment=0
    )
    story.append(Paragraph("CLASSIFICATION: COMMERCIAL CONFIDENTIAL // PHISHZERO THREAT ENGINE REPORT", confidential_style))
    story.append(PageBreak())


def make_progress_bar(score, verdict_color):
    width_active = max(1, score * 5.04)
    width_inactive = max(1, (100 - score) * 5.04)
    bar_table = Table([['', '']], colWidths=[width_active, width_inactive], rowHeights=[14])
    bar_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), verdict_color),
        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    return bar_table


def make_recommendations_section(verdict_text, score, heading_style, cell_regular):
    story_parts = []
    story_parts.append(make_heading("Security Analyst Recommendations", heading_style))
    
    recs = []
    if verdict_text == 'PHISHING':
        recs = [
            "<b>DO NOT ENTER PASSWORDS OR CREDENTIALS</b>: This domain shows extreme indicators of credential harvesting.",
            "<b>DO NOT DOWNLOAD ATTACHMENTS/FILES</b>: File payloads from this source may host trojans or ransomware.",
            "<b>REPORT DOMAIN IMMEDIATELY</b>: Flag this URL inside your email client or submit it to public blacklists.",
            "<b>USE OFFICIAL CHANNELS</b>: Access the intended service only through official bookmarked links."
        ]
    elif verdict_text == 'SUSPICIOUS':
        recs = [
            "<b>VERIFY CERTIFICATE LIFECYCLE</b>: The domain's SSL layer has anomalies or is expiring soon.",
            "<b>CONFIRM SENDER DETAILS</b>: Reach out to the sender via trusted channels to confirm intent.",
            "<b>INSPECT REDIRECT PATHS</b>: Check the network connections triggered by this URL before logging in.",
            "<b>ENABLE MULTI-FACTOR AUTHENTICATION</b>: Ensure MFA is active on all associated accounts."
        ]
    else:
        recs = [
            "<b>CONTINUE MONITORING</b>: Although scanned as clean, always exercise active caution with external links.",
            "<b>USE AN ANTI-PHISHING EXTENSION</b>: Keep browser extensions active to prevent typosquatting attacks.",
            "<b>KEEP SYSTEMS PATCHED</b>: Ensure your operating system and web browser security updates are installed."
        ]
        
    rec_table_data = []
    for r in recs:
        bullet = Paragraph("<font name='Helvetica-Bold' color='#00d4ff'>&#9656;</font>", cell_regular)
        text = Paragraph(r, cell_regular)
        rec_table_data.append([bullet, text])
        
    rec_table = Table(rec_table_data, colWidths=[15, 489])
    rec_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story_parts.append(rec_table)
    return story_parts


def make_checklist_section(scan_data, heading_style, cell_bold, cell_regular):
    story_parts = []
    story_parts.append(make_heading("Critical Security Checklist", heading_style))
    
    rows = [
        [Paragraph("Security Parameter", cell_bold), Paragraph("Verification Check", cell_bold), Paragraph("Status", cell_bold)]
    ]
    
    def format_badge(status_tuple):
        label, color = status_tuple
        return make_badge(label, color)
        
    if 'sender_analysis' in scan_data:
        # Email Check
        sender = scan_data.get('sender_analysis', {})
        body = scan_data.get('body_analysis', {})
        links = scan_data.get('link_analysis', [])
        
        has_public_provider = sender.get('is_public_provider', False)
        sender_status = ("WARNING", colors.HexColor('#d97706')) if has_public_provider else ("PASS", colors.HexColor('#047857'))
        
        has_urgency = body.get('urgency_count', 0) > 0 or len(body.get('phishing_keywords', [])) > 0
        urgency_status = ("FAIL", colors.HexColor('#b91c1c')) if has_urgency else ("PASS", colors.HexColor('#047857'))
        
        has_phish_links = any(link.get('verdict') in ['Phishing', 'Suspicious'] for link in links)
        links_status = ("FAIL", colors.HexColor('#b91c1c')) if has_phish_links else ("PASS", colors.HexColor('#047857'))
        
        rows.extend([
            [Paragraph("Sender Authenticity", cell_regular), Paragraph("Validates sender domain is not a public mail provider", cell_regular), format_badge(sender_status)],
            [Paragraph("Urgency & Language Heuristics", cell_regular), Paragraph("Scans subject and body for threat/urgency syntax", cell_regular), format_badge(urgency_status)],
            [Paragraph("Hyperlink Destination Review", cell_regular), Paragraph("Scans embedded URLs inside email for phishing targets", cell_regular), format_badge(links_status)]
        ])
    elif 'filetype' in scan_data:
        # File/Binary Check
        file_type = scan_data.get('filetype', 'apk')
        high_risk = scan_data.get('high_risk_permissions', [])
        url_scans = scan_data.get('url_scans', [])
        stego = scan_data.get('stego_payload')
        
        if file_type == 'apk':
            perm_status = ("FAIL", colors.HexColor('#b91c1c')) if len(high_risk) > 0 else ("PASS", colors.HexColor('#047857'))
            url_status = ("FAIL", colors.HexColor('#b91c1c')) if any(u.get('verdict') in ['Phishing', 'Suspicious'] for u in url_scans) else ("PASS", colors.HexColor('#047857'))
            rows.extend([
                [Paragraph("High-Risk APK Permissions", cell_regular), Paragraph("Checks AndroidManifest.xml for dangerous permission requests", cell_regular), format_badge(perm_status)],
                [Paragraph("Embedded Threat Hyperlinks", cell_regular), Paragraph("Audits hardcoded URLs parsed inside dex files", cell_regular), format_badge(url_status)]
            ])
        else:
            # Image
            stego_status = ("FAIL", colors.HexColor('#b91c1c')) if stego else ("PASS", colors.HexColor('#047857'))
            qr_url = scan_data.get('qr_url')
            qr_status = ("FAIL", colors.HexColor('#b91c1c')) if qr_url and any(u.get('verdict') in ['Phishing', 'Suspicious'] for u in url_scans) else ("PASS", colors.HexColor('#047857'))
            rows.extend([
                [Paragraph("Steganography Detection", cell_regular), Paragraph("Scans image binary streams for appended payload offsets", cell_regular), format_badge(stego_status)],
                [Paragraph("QR Code Vector Audit", cell_regular), Paragraph("Decodes QR matrices and checks URL safety verdicts", cell_regular), format_badge(qr_status)]
            ])
    else:
        # URL Check
        results = scan_data.get('results', [])
        ssl_info = scan_data.get('ssl', {})
        whois_info = scan_data.get('whois', {})
        
        has_https = not any(sig.get('name') == "No HTTPS" and sig.get('triggered') for sig in results)
        https_status = ("PASS", colors.HexColor('#047857')) if has_https else ("FAIL", colors.HexColor('#b91c1c'))
        
        has_ssl = ssl_info.get('valid', False) and not ssl_info.get('error')
        ssl_status = ("PASS", colors.HexColor('#047857')) if has_ssl else ("FAIL", colors.HexColor('#b91c1c'))
        
        has_whois = not whois_info.get('error')
        whois_status = ("PASS", colors.HexColor('#047857')) if has_whois else ("WARNING", colors.HexColor('#d97706'))
        
        age = whois_info.get('age_days', 365)
        age_status = ("PASS", colors.HexColor('#047857')) if age >= 30 else ("FAIL", colors.HexColor('#b91c1c'))
        
        brand_impersonation = any(sig.get('name') == "Brand Impersonation" and sig.get('triggered') for sig in results)
        brand_status = ("FAIL", colors.HexColor('#b91c1c')) if brand_impersonation else ("PASS", colors.HexColor('#047857'))
        
        keywords = any(sig.get('name') == "Phishing Keywords" and sig.get('triggered') for sig in results)
        keyword_status = ("FAIL", colors.HexColor('#b91c1c')) if keywords else ("PASS", colors.HexColor('#047857'))
        
        rows.extend([
            [Paragraph("HTTPS Deployment", cell_regular), Paragraph("Verifies secure protocol handshake over SSL", cell_regular), format_badge(https_status)],
            [Paragraph("SSL Integrity Check", cell_regular), Paragraph("Validates certificate trust and expiration thresholds", cell_regular), format_badge(ssl_status)],
            [Paragraph("WHOIS Query", cell_regular), Paragraph("Retrieves public registrar records for domain authenticity", cell_regular), format_badge(whois_status)],
            [Paragraph("Domain Age Baseline", cell_regular), Paragraph("Checks if domain was registered at least 30 days ago", cell_regular), format_badge(age_status)],
            [Paragraph("Brand Masquerading", cell_regular), Paragraph("Scans hostnames for typosquatting or brand impersonation", cell_regular), format_badge(brand_status)],
            [Paragraph("Lexical Keyword Check", cell_regular), Paragraph("Scans URL strings for known harvesting keywords", cell_regular), format_badge(keyword_status)]
        ])
        
    tbl = Table(rows, colWidths=[150, 274, 80])
    tbl_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (2, 1), (2, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]
    for i in range(1, len(rows)):
        bg = colors.HexColor('#f8fafc') if i % 2 == 0 else colors.white
        tbl_styles.append(('BACKGROUND', (0, i), (-1, i), bg))
        
    tbl.setStyle(TableStyle(tbl_styles))
    story_parts.append(KeepTogether([tbl]))
    return story_parts


def make_timeline_section(scan_data, heading_style, cell_bold, cell_regular):
    story_parts = []
    story_parts.append(make_heading("Security Timeline", heading_style))
    
    scan_date = datetime.now().strftime('%Y-%m-%d')
    
    if 'sender_analysis' in scan_data:
        rows = [
            [Paragraph("Security Milestone", cell_bold), Paragraph("Date Reference", cell_bold), Paragraph("Details & Context", cell_bold)],
            [Paragraph("Mail Reception / Extraction", cell_regular), Paragraph(str(scan_date), cell_regular), Paragraph("Ingested into PhishZero email sandbox", cell_regular)],
            [Paragraph("Headers & SPF Validation", cell_regular), Paragraph(str(scan_date), cell_regular), Paragraph("Sender authentication completed", cell_regular)],
            [Paragraph("Deep Content Threat Scan", cell_regular), Paragraph(str(scan_date), cell_regular), Paragraph("Body heuristics and layout parsing completed", cell_regular)]
        ]
    elif 'filetype' in scan_data:
        file_type = scan_data.get('filetype', 'apk').upper()
        rows = [
            [Paragraph("Security Milestone", cell_bold), Paragraph("Date Reference", cell_bold), Paragraph("Details & Context", cell_bold)],
            [Paragraph("Binary File Uploaded", cell_regular), Paragraph(str(scan_date), cell_regular), Paragraph(f"Uploaded {file_type} binary target", cell_regular)],
            [Paragraph("Disassembly & Parsing", cell_regular), Paragraph(str(scan_date), cell_regular), Paragraph("Manifest and binary payload parsed", cell_regular)],
            [Paragraph("Threat Sandbox Analysis", cell_regular), Paragraph(str(scan_date), cell_regular), Paragraph("Heuristic signatures and URLs checked", cell_regular)]
        ]
    else:
        whois_info = scan_data.get('whois', {})
        ssl_info = scan_data.get('ssl', {})
        created_date = whois_info.get('creation_date', 'N/A')
        expiry_date = ssl_info.get('expiry_date', 'N/A')
        age_days = whois_info.get('age_days', 0)
        
        rows = [
            [Paragraph("Security Milestone", cell_bold), Paragraph("Registered Date", cell_bold), Paragraph("Details & Age Reference", cell_bold)],
            [Paragraph("Domain Creation Date", cell_regular), Paragraph(str(created_date), cell_regular), Paragraph(f"Active for {age_days} days" if age_days > 0 else "Age record missing", cell_regular)],
            [Paragraph("SSL Certificate Expiration", cell_regular), Paragraph(str(expiry_date), cell_regular), Paragraph(f"Expires in {ssl_info.get('days_left', 0)} days" if ssl_info.get('valid') else "Invalid/No SSL certificate", cell_regular)],
            [Paragraph("PhishZero Threat Scan", cell_regular), Paragraph(str(scan_date), cell_regular), Paragraph("Threat analysis executed dynamically", cell_regular)]
        ]
        
    tbl = Table(rows, colWidths=[150, 120, 234])
    tbl_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]
    for i in range(1, len(rows)):
        bg = colors.HexColor('#f8fafc') if i % 2 == 0 else colors.white
        tbl_styles.append(('BACKGROUND', (0, i), (-1, i), bg))
        
    tbl.setStyle(TableStyle(tbl_styles))
    story_parts.append(KeepTogether([tbl]))
    return story_parts


def make_badge(label, bg_color):
    """
    Helper to generate a cleanly styled colored rectangle badge flowable.
    """
    badge_style = ParagraphStyle(
        'BadgeText',
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=9,
        textColor=colors.white,
        alignment=1 # Centered
    )
    badge_p = Paragraph(label, badge_style)
    t = Table([[badge_p]], colWidths=[60], rowHeights=[16])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
    ]))
    return t


def make_heading(text, heading_style):
    # Left accent bar accentuating the section heading
    accent_bar = Table([['']], colWidths=[4], rowHeights=[14])
    accent_bar.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#3b82f6')), # Cyber Blue accent
        ('PADDING', (0, 0), (-1, -1), 0),
    ]))
    
    t = Table([[accent_bar, Paragraph(text, heading_style)]], colWidths=[10, 494])
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    t.spaceBefore = 18
    t.spaceAfter = 10
    return t


def generate_url_pdf(scan_data, logo_source="logo.png"):
    """
    Generates a premium, clean layout security audit PDF report
    with enhanced typography, structured cards, and visual accents.
    
    :param logo_source: Path to the logo file, or an io.BytesIO stream containing the image data.
    """
    buffer = io.BytesIO()
    
    # Page setup
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    # Premium Typography Styles
    title_style = ParagraphStyle(
        'ReportTitle',
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=0
    )
    
    meta_style = ParagraphStyle(
        'ReportMeta',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=12,
        textColor=colors.HexColor('#38bdf8'), # Tech vibrant cyan
        alignment=0
    )
    
    heading_style = ParagraphStyle(
        'SectionHeading',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=0,
        spaceBefore=0
    )
    
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#0f172a')
    )
    
    cell_regular = ParagraphStyle(
        'CellRegular',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#475569')
    )

    verdict_text = scan_data.get('verdict', 'Safe').upper()
    score = scan_data.get('score', 0)
    url = scan_data.get('url', 'N/A')
    
    # Context-aware color themes
    if verdict_text == 'PHISHING':
        verdict_color = colors.HexColor('#991b1b') # Crimson
        verdict_label = "CRITICAL: PHISHING THREAT DETECTED"
    elif verdict_text == 'SUSPICIOUS':
        verdict_color = colors.HexColor('#c2410c') # Rust orange
        verdict_label = "WARNING: SUSPICIOUS ACTIVITY INDICATORS"
    else:
        verdict_color = colors.HexColor('#065f46') # Deep Forest Green
        verdict_label = "VERDICT: CLEAN / UNCOMPROMISED"

    title_text = "Phishing URL Analysis Report" if verdict_text == 'PHISHING' else "Website Security Analysis Report"

    story = []
    
    # 0. Add Cover Page
    add_cover_page(story, scan_data, title_text, logo_source)

    # 1. Header Hero Block (Asymmetric Two-Column Brand Layout)
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    meta_text = f"AUDIT TIMESTAMP: {date_str}  //  ENGINE: RUNTIME V1.0"
    
    # Left column content (Metadata and Text Title)
    left_content = [
        Paragraph(meta_text, meta_style),
        Spacer(1, 4),
        Paragraph(title_text, title_style)
    ]
    
    # Right column content (Logo image flowable)
    right_content = []
    import os
    if logo_source and ((isinstance(logo_source, str) and os.path.exists(logo_source)) or not isinstance(logo_source, str)):
        try:
            logo_img = Image(logo_source, width=110, height=24)
            logo_img.hAlign = 'RIGHT'
            right_content.append(logo_img)
        except Exception:
            logo_img = None
    else:
        logo_img = None

    if not logo_img:
        # Fallback to plain text tool identifier if the logo file is missing/unreadable
        fallback_style = ParagraphStyle('FallbackLogo', fontName='Helvetica-Bold', fontSize=14, textColor=colors.HexColor('#0f172a'), alignment=2)
        right_content.append(Paragraph("Phish<b>Zero</b>", fallback_style))

    # Construct the split header grid
    header_table = Table([[left_content, right_content]], colWidths=[360, 144])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 16),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 16),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
        ('LINEBELOW', (0, -1), (-1, -1), 2.5, colors.HexColor('#0f172a')), # Strong slate structural bar
    ]))
    story.append(header_table)
    story.append(Spacer(1, 14))

    # 2. Modern Segmented Verdict Banner
    banner_verdict_label_style = ParagraphStyle(
        'BannerVerdictLabel',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.white,
        alignment=0
    )
    
    banner_score_style = ParagraphStyle(
        'BannerScore',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.white,
        alignment=2
    )

    banner_table = Table([
        [
            Paragraph(verdict_label, banner_verdict_label_style),
            Paragraph(f"RISK INDEX: {score} / 100", banner_score_style)
        ]
    ], colWidths=[334, 170])
    
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 8))
    story.append(make_progress_bar(score, verdict_color))
    story.append(Spacer(1, 14))

    # 3. Analyzed Target Information Card
    story.append(make_heading("Analyzed Target URL", heading_style))
    
    url_para_style = ParagraphStyle(
        'UrlPara',
        fontName='Courier-Bold', # Monospace font for security indicators
        fontSize=9,
        leading=14,
        textColor=colors.HexColor('#0f172a'),
    )
    
    url_card = Table([[Paragraph(url, url_para_style)]], colWidths=[504])
    url_card.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
        ('BORDER', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(url_card)

    # 4. Threat Factor Matrix
    story.append(make_heading("Identified Risk Profiles & Signatures", heading_style))
    
    results = scan_data.get('results', [])
    ssl_info = scan_data.get('ssl', {})
    whois_info = scan_data.get('whois', {})
    
    risk_rows = []
    
    # Heuristic Checks
    domain_does_not_resolve = False
    if whois_info.get('error') or whois_info.get('age_days', 0) == 0 or whois_info.get('registrar', 'N/A') == 'N/A':
        domain_does_not_resolve = True
        
    if domain_does_not_resolve:
        badge = make_badge("CRITICAL", colors.HexColor('#b91c1c'))
        desc_p = Paragraph("<b>Domain resolution failure</b> — The server layout could not resolve or is purposefully inactive.", cell_regular)
        risk_rows.append([badge, desc_p])
        
    for sig in results:
        if sig.get('triggered'):
            name = sig.get('name')
            pts = sig.get('points', 0)
            
            if name == "No HTTPS":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                desc_p = Paragraph("<b>Missing transport layer encryption</b> — Traffic is vulnerable to interception.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Suspicious TLD":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                extracted_domain = tldextract.extract(url)
                tld_name = f".{extracted_domain.suffix}" if extracted_domain.suffix else ".tk"
                desc_p = Paragraph(f"<b>Unreliable Top-Level Domain</b> — {tld_name} is statistically associated with unsafe setups.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Phishing Keywords":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                from url_checker import PHISHING_KEYWORDS
                keywords_triggered = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
                keywords_str = ", ".join(keywords_triggered) if keywords_triggered else "login, verify, secure, account, confirm"
                desc_p = Paragraph(f"<b>Deceptive string elements detected</b>: <font name='Courier-Bold'>{keywords_str}</font>", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Hyphen in Domain":
                badge = make_badge("LOW", colors.HexColor('#2563eb'))
                desc_p = Paragraph("<b>Hyphenation separator present</b> — Frequently deployed in typosquatting masquerades.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Digits in Domain":
                badge = make_badge("LOW", colors.HexColor('#2563eb'))
                desc_p = Paragraph("<b>Numerical inclusions</b> — Domain naming format exhibits machine-generated anomalies.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Brand Impersonation":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                desc_p = Paragraph("<b>High-affinity trademark match</b> — Target looks designed to imitate trusted entities.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name not in ["IP as Host", "Shortener Domain", "Subdomain Depth", "URL Length", "Hex Encoding", "Double Slash"]:
                if pts >= 25:
                    badge = make_badge("CRITICAL", colors.HexColor('#b91c1c'))
                elif pts >= 15:
                    badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                elif pts >= 8:
                    badge = make_badge("MEDIUM", colors.HexColor('#d97706'))
                else:
                    badge = make_badge("LOW", colors.HexColor('#2563eb'))
                desc_p = Paragraph(f"<b>{name}</b> — {sig.get('description', '')}", cell_regular)
                risk_rows.append([badge, desc_p])
                
    if not domain_does_not_resolve:
        if not ssl_info.get('valid'):
            badge = make_badge("CRITICAL", colors.HexColor('#b91c1c'))
            desc_p = Paragraph("<b>Broken SSL/TLS Framework</b> — Cryptographic validation handshake failed completely.", cell_regular)
            risk_rows.append([badge, desc_p])
        elif ssl_info.get('warning'):
            badge = make_badge("HIGH", colors.HexColor('#ea580c'))
            desc_p = Paragraph(f"<b>Imminent Certificate Expiry</b> — Validation window ends in ({ssl_info.get('days_left', 0)} days).", cell_regular)
            risk_rows.append([badge, desc_p])
            
    if not risk_rows:
        badge = make_badge("CLEAN", colors.HexColor('#047857'))
        desc_p = Paragraph("No threat signatures or tactical threat vectors were triggered during this sandbox evaluation.", cell_regular)
        risk_rows.append([badge, desc_p])
        
    risk_table = Table(risk_rows, colWidths=[75, 429])
    risk_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (1, 0), (1, -1), 10),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#f1f5f9')),
    ]))
    story.append(KeepTogether([risk_table]))

    # 5. Technical Parameter Grid
    story.append(make_heading("Detailed Diagnostics & Metrics", heading_style))
    
    url_len = f"{len(url)} characters"
    https_status = "True" if url.lower().startswith('https://') else "False"
    
    extracted = tldextract.extract(url)
    tld_val = f".{extracted.suffix}" if extracted.suffix else "None"
    
    subdomain_parts = [p for p in extracted.subdomain.split('.') if p]
    subdomain_depth = str(len(subdomain_parts))
    
    from url_checker import PHISHING_KEYWORDS
    keywords_triggered = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
    keywords_val = f"{len(keywords_triggered)} verified" if keywords_triggered else "0 verified"
    
    ssl_status = "Valid" if ssl_info.get('valid') else "Invalid"
    ssl_expiry = f"{ssl_info.get('expiry_date', 'N/A')} ({ssl_info.get('days_left', 0)}d left)" if ssl_info.get('valid') else "N/A"
    
    age_days = whois_info.get('age_days', 0)
    domain_age = f"{age_days} days" if age_days > 0 else "N/A"
    registrar_val = whois_info.get('registrar', 'N/A')
    
    tech_rows = [
        [Paragraph("Security Vector", cell_bold), Paragraph("Observed State / Metrical Signature", cell_bold)],
        [Paragraph("Full URL Length", cell_regular), Paragraph(url_len, cell_regular)],
        [Paragraph("Secure Protocol Deployment (HTTPS)", cell_regular), Paragraph(https_status, cell_regular)],
        [Paragraph("Registered TLD Suffix", cell_regular), Paragraph(tld_val, cell_regular)],
        [Paragraph("Subdomain Node Context Depth", cell_regular), Paragraph(subdomain_depth, cell_regular)],
        [Paragraph("Lexical Fraud Indicators", cell_regular), Paragraph(keywords_val, cell_regular)],
        [Paragraph("SSL Layer Authentication", cell_regular), Paragraph(ssl_status, cell_regular)],
        [Paragraph("SSL Lifecycle Threshold", cell_regular), Paragraph(ssl_expiry, cell_regular)],
        [Paragraph("Registrant Domain Baseline Age", cell_regular), Paragraph(domain_age, cell_regular)],
        [Paragraph("Authority Registrar Assignment", cell_regular), Paragraph(registrar_val, cell_regular)]
    ]
    
    tech_table = Table(tech_rows, colWidths=[230, 274])
    
    tech_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')), # Clean crisp gray header
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]
    
    # Asymmetric subtle row striping
    for r_idx in range(1, len(tech_rows)):
        bg = colors.HexColor('#f8fafc') if r_idx % 2 == 0 else colors.white
        tech_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
        
    tech_table.setStyle(TableStyle(tech_styles))
    story.append(KeepTogether([tech_table]))
    
    # 6. Checklist, Timeline & Recommendations
    story.extend(make_checklist_section(scan_data, heading_style, cell_bold, cell_regular))
    story.extend(make_timeline_section(scan_data, heading_style, cell_bold, cell_regular))
    story.extend(make_recommendations_section(verdict_text, score, heading_style, cell_regular))

    # Build Document Execution Flow
    doc.build(story, canvasmaker=NumberedCanvas)
    
    buffer.seek(0)
    return buffer.getvalue()


def generate_email_pdf(scan_data, logo_source="logo.png"):
    """
    Generates a premium, clean layout security audit PDF report for emails.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'ReportTitle',
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=0
    )
    
    meta_style = ParagraphStyle(
        'ReportMeta',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=12,
        textColor=colors.HexColor('#38bdf8'),
        alignment=0
    )
    
    heading_style = ParagraphStyle(
        'SectionHeading',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=0,
        spaceBefore=0
    )
    
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#0f172a')
    )
    
    cell_regular = ParagraphStyle(
        'CellRegular',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#475569')
    )

    verdict_text = scan_data.get('verdict', 'Safe').upper()
    score = scan_data.get('score', 0)
    
    if verdict_text == 'PHISHING':
        verdict_color = colors.HexColor('#991b1b')
        verdict_label = "CRITICAL: PHISHING THREAT DETECTED"
    elif verdict_text == 'SUSPICIOUS':
        verdict_color = colors.HexColor('#c2410c')
        verdict_label = "WARNING: SUSPICIOUS ACTIVITY INDICATORS"
    else:
        verdict_color = colors.HexColor('#065f46')
        verdict_label = "VERDICT: CLEAN / UNCOMPROMISED"

    story = []
    
    # 0. Add Cover Page
    add_cover_page(story, scan_data, "Email Security Analysis Report", logo_source)

    # 1. Header Hero Block
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    meta_text = f"AUDIT TIMESTAMP: {date_str}  //  ENGINE: MAIL_SCANNER V1.0"
    
    title_text = "Email Security Analysis Report"
    
    left_content = [
        Paragraph(meta_text, meta_style),
        Spacer(1, 4),
        Paragraph(title_text, title_style)
    ]
    
    right_content = []
    import os
    if logo_source and ((isinstance(logo_source, str) and os.path.exists(logo_source)) or not isinstance(logo_source, str)):
        try:
            logo_img = Image(logo_source, width=110, height=24)
            logo_img.hAlign = 'RIGHT'
            right_content.append(logo_img)
        except Exception:
            logo_img = None
    else:
        logo_img = None

    if not logo_img:
        fallback_style = ParagraphStyle('FallbackLogo', fontName='Helvetica-Bold', fontSize=14, textColor=colors.HexColor('#0f172a'), alignment=2)
        right_content.append(Paragraph("Phish<b>Zero</b>", fallback_style))

    header_table = Table([[left_content, right_content]], colWidths=[360, 144])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 16),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 16),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
        ('LINEBELOW', (0, -1), (-1, -1), 2.5, colors.HexColor('#0f172a')),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 14))

    # 2. Verdict Banner
    banner_verdict_label_style = ParagraphStyle(
        'BannerVerdictLabel',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.white,
        alignment=0
    )
    
    banner_score_style = ParagraphStyle(
        'BannerScore',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.white,
        alignment=2
    )

    banner_table = Table([
        [
            Paragraph(verdict_label, banner_verdict_label_style),
            Paragraph(f"RISK INDEX: {score} / 100", banner_score_style)
        ]
    ], colWidths=[334, 170])
    
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 8))
    story.append(make_progress_bar(score, verdict_color))
    story.append(Spacer(1, 14))

    # 3. Sender & Content Diagnostics Grid
    story.append(make_heading("Sender & Content Diagnostics", heading_style))
    
    sender_analysis = scan_data.get('sender_analysis', {})
    body_analysis = scan_data.get('body_analysis', {})
    
    sender_email = sender_analysis.get('email', 'N/A')
    sender_domain = sender_analysis.get('domain', 'N/A')
    free_provider_status = "Yes (Public Free Provider)" if sender_analysis.get('is_free_provider') else "No (Private Corporate/Auth Domain)"
    brand_spoof_status = f"Yes (Impersonating {sender_analysis.get('impersonated_brand')})" if sender_analysis.get('is_spoofed_brand') else "None Detected"
    
    generic_greeting_status = f"Yes ('{body_analysis.get('generic_greeting_text')}')" if body_analysis.get('generic_greeting') else "No (Personalized/Normal)"
    sensitive_req_status = "Yes (Asks for Credentials, Cards, or PINs)" if body_analysis.get('sensitive_info_requested') else "No Sensitive Data Fields Requested"
    
    urg_kws = body_analysis.get('urgent_keywords_found', [])
    urgency_status = ", ".join(urg_kws) if urg_kws else "None Detected"
    
    diag_rows = [
        [Paragraph("Audit Vector", cell_bold), Paragraph("Observed State / Details", cell_bold)],
        [Paragraph("Declared Sender Address", cell_regular), Paragraph(sender_email, cell_regular)],
        [Paragraph("Sender Mailserver Domain", cell_regular), Paragraph(sender_domain, cell_regular)],
        [Paragraph("Public Mail Server Flag", cell_regular), Paragraph(free_provider_status, cell_regular)],
        [Paragraph("Brand Identity Impersonation", cell_regular), Paragraph(brand_spoof_status, cell_regular)],
        [Paragraph("Generic Greetings Audit", cell_regular), Paragraph(generic_greeting_status, cell_regular)],
        [Paragraph("Credential Requests Flag", cell_regular), Paragraph(sensitive_req_status, cell_regular)],
        [Paragraph("Urgency/Fear-Inducing Lexicon", cell_regular), Paragraph(urgency_status, cell_regular)]
    ]
    
    diag_table = Table(diag_rows, colWidths=[200, 304])
    diag_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]
    
    for r_idx in range(1, len(diag_rows)):
        bg = colors.HexColor('#f8fafc') if r_idx % 2 == 0 else colors.white
        diag_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
        
    diag_table.setStyle(TableStyle(diag_styles))
    story.append(KeepTogether([diag_table]))
    story.append(Spacer(1, 10))

    # 4. Triggered Email Risk Signatures
    story.append(make_heading("Identified Phishing Signals", heading_style))
    results = scan_data.get('results', [])
    risk_rows = []
    
    for rule in results:
        points = rule.get('points', 0)
        if points >= 25:
            badge = make_badge("CRITICAL", colors.HexColor('#b91c1c'))
        elif points >= 15:
            badge = make_badge("HIGH", colors.HexColor('#ea580c'))
        elif points >= 10:
            badge = make_badge("MEDIUM", colors.HexColor('#d97706'))
        else:
            badge = make_badge("LOW", colors.HexColor('#2563eb'))
            
        desc_p = Paragraph(f"<b>{rule.get('name')} (+{points} pts)</b> — {rule.get('description', '')}", cell_regular)
        risk_rows.append([badge, desc_p])
        
    if not risk_rows:
        badge = make_badge("CLEAN", colors.HexColor('#047857'))
        desc_p = Paragraph("No suspicious email heuristic signatures or content anomalies were triggered during this check.", cell_regular)
        risk_rows.append([badge, desc_p])
        
    risk_table = Table(risk_rows, colWidths=[75, 429])
    risk_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (1, 0), (1, -1), 10),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#f1f5f9')),
    ]))
    story.append(KeepTogether([risk_table]))
    story.append(Spacer(1, 10))

    # 5. Embedded Links Threat Table
    link_analysis = scan_data.get('link_analysis', {})
    flagged_links = link_analysis.get('flagged_links', [])
    total_links = link_analysis.get('total_links', 0)
    
    story.append(make_heading(f"Embedded Links Analysis ({total_links} links total, {len(flagged_links)} suspicious)", heading_style))
    
    if flagged_links:
        link_rows = [
            [Paragraph("Displayed Link Text", cell_bold), Paragraph("Actual Destination URL", cell_bold), Paragraph("Risk Score", cell_bold)]
        ]
        for link in flagged_links:
            display_txt = link.get('displayed', '')
            actual_url = link.get('actual', '')
            score_val = link.get('score', 0)
            is_spoofed = link.get('is_spoofed', False)
            
            display_style = ParagraphStyle('DisplayLink', parent=cell_regular, fontName='Helvetica-Bold' if is_spoofed else 'Helvetica')
            display_text_p = Paragraph(f"{display_txt}<br/><font color='#ef4444'>[!] Display Hijack</font>" if is_spoofed else display_txt, display_style)
            
            actual_text_p = Paragraph(f"<font face='Courier-Bold' size='7'>{actual_url}</font>", cell_regular)
            score_text_p = Paragraph(f"<b>{score_val}/100</b>", cell_regular)
            
            link_rows.append([display_text_p, actual_text_p, score_text_p])
            
        link_table = Table(link_rows, colWidths=[150, 300, 54])
        link_styles = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ]
        
        for r_idx in range(1, len(link_rows)):
            bg = colors.HexColor('#f8fafc') if r_idx % 2 == 0 else colors.white
            link_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
            
        link_table.setStyle(TableStyle(link_styles))
        story.append(KeepTogether([link_table]))
    else:
        no_links_p = Paragraph("No suspicious or flagged links were parsed inside the email text body.", cell_regular)
        story.append(no_links_p)
        
    # 4. Checklist, Timeline & Recommendations
    story.extend(make_checklist_section(scan_data, heading_style, cell_bold, cell_regular))
    story.extend(make_timeline_section(scan_data, heading_style, cell_bold, cell_regular))
    story.extend(make_recommendations_section(verdict_text, score, heading_style, cell_regular))

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def generate_file_pdf(scan_data, logo_source="logo.png"):
    """
    Generates a premium, clean layout security audit PDF report for APK and image threat sandbox files.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'ReportTitle',
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=0
    )
    
    meta_style = ParagraphStyle(
        'ReportMeta',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=12,
        textColor=colors.HexColor('#38bdf8'),
        alignment=0
    )
    
    heading_style = ParagraphStyle(
        'SectionHeading',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=0,
        spaceBefore=0
    )
    
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#0f172a')
    )
    
    cell_regular = ParagraphStyle(
        'CellRegular',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#475569')
    )

    verdict_text = scan_data.get('verdict', 'Safe').upper()
    score = scan_data.get('score', 0)
    filename = scan_data.get('filename', 'N/A')
    filesize = scan_data.get('filesize', 0)
    filetype = scan_data.get('filetype', 'apk')
    
    def format_bytes(b):
        if b == 0: return '0 Bytes'
        k = 1024
        sizes = ['Bytes', 'KB', 'MB', 'GB']
        import math
        i = int(math.floor(math.log(b) / math.log(k)))
        return f"{round(b / (k ** i), 2)} {sizes[i]}"
        
    formatted_size = format_bytes(filesize)

    if verdict_text == 'PHISHING':
        verdict_color = colors.HexColor('#991b1b')
        verdict_label = "CRITICAL: HIGH MALICIOUS RISK DETECTED"
    elif verdict_text == 'SUSPICIOUS':
        verdict_color = colors.HexColor('#c2410c')
        verdict_label = "WARNING: SUSPICIOUS FILE INDICATORS"
    else:
        verdict_color = colors.HexColor('#065f46')
        verdict_label = "VERDICT: SAFE / CLEAN FILE"

    story = []
    
    # 0. Add Cover Page
    add_cover_page(story, scan_data, "File Threat Sandbox Report", logo_source)

    # 1. Header Hero Block
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    meta_text = f"AUDIT TIMESTAMP: {date_str}  //  ENGINE: SANDBOX_SCANNER V1.0"
    
    title_text = "File Threat Sandbox Report"
    
    left_content = [
        Paragraph(meta_text, meta_style),
        Spacer(1, 4),
        Paragraph(title_text, title_style)
    ]
    
    right_content = []
    import os
    if logo_source and ((isinstance(logo_source, str) and os.path.exists(logo_source)) or not isinstance(logo_source, str)):
        try:
            logo_img = Image(logo_source, width=110, height=24)
            logo_img.hAlign = 'RIGHT'
            right_content.append(logo_img)
        except Exception:
            logo_img = None
    else:
        logo_img = None

    if not logo_img:
        fallback_style = ParagraphStyle('FallbackLogo', fontName='Helvetica-Bold', fontSize=14, textColor=colors.HexColor('#0f172a'), alignment=2)
        right_content.append(Paragraph("Phish<b>Zero</b>", fallback_style))

    header_table = Table([[left_content, right_content]], colWidths=[360, 144])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 16),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 16),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
        ('LINEBELOW', (0, -1), (-1, -1), 2.5, colors.HexColor('#0f172a')),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 14))

    # 2. Verdict Banner
    banner_verdict_label_style = ParagraphStyle(
        'BannerVerdictLabel',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.white,
        alignment=0
    )
    
    banner_score_style = ParagraphStyle(
        'BannerScore',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.white,
        alignment=2
    )

    banner_table = Table([
        [
            Paragraph(verdict_label, banner_verdict_label_style),
            Paragraph(f"RISK INDEX: {score} / 100", banner_score_style)
        ]
    ], colWidths=[334, 170])
    
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 8))
    story.append(make_progress_bar(score, verdict_color))
    story.append(Spacer(1, 14))

    # 3. File Properties Card
    story.append(make_heading("File Properties", heading_style))
    
    extracted_urls = scan_data.get('extracted_urls', [])
    
    prop_rows = [
        [Paragraph("Property", cell_bold), Paragraph("Value", cell_bold)],
        [Paragraph("File Name", cell_regular), Paragraph(filename, cell_regular)],
        [Paragraph("File Size", cell_regular), Paragraph(formatted_size, cell_regular)],
        [Paragraph("Inferred File Type", cell_regular), Paragraph(filetype.upper(), cell_regular)],
        [Paragraph("Extracted Hardcoded Domains", cell_regular), Paragraph(f"{len(extracted_urls)} found", cell_regular)]
    ]
    
    prop_table = Table(prop_rows, colWidths=[200, 304])
    prop_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]
    for r_idx in range(1, len(prop_rows)):
        bg = colors.HexColor('#f8fafc') if r_idx % 2 == 0 else colors.white
        prop_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
        
    prop_table.setStyle(TableStyle(prop_styles))
    story.append(KeepTogether([prop_table]))
    story.append(Spacer(1, 10))

    # 4. APK/Image Sandbox Specific details
    if filetype == 'apk':
        story.append(make_heading("Android Manifest Analysis (High-Risk Permissions)", heading_style))
        high_risk_permissions = scan_data.get('high_risk_permissions', [])
        
        perm_rows = []
        for p in high_risk_permissions:
            badge = make_badge("HIGH RISK", colors.HexColor('#ef4444'))
            desc_p = Paragraph(f"<b>{p.get('permission')}</b><br/>{p.get('description', '')}", cell_regular)
            perm_rows.append([badge, desc_p])
            
        if not perm_rows:
            badge = make_badge("CLEAN", colors.HexColor('#047857'))
            desc_p = Paragraph("No high-risk security access permissions were identified in the Android Manifest.", cell_regular)
            perm_rows.append([badge, desc_p])
            
        perm_table = Table(perm_rows, colWidths=[75, 429])
        perm_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (1, 0), (1, -1), 10),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#f1f5f9')),
        ]))
        story.append(KeepTogether([perm_table]))
        story.append(Spacer(1, 10))
        
        # General list of permissions
        permissions = scan_data.get('permissions', [])
        if permissions:
            story.append(make_heading("All Declared App Permissions", heading_style))
            simple_perms = [perm.replace('android.permission.', '') for perm in permissions]
            perms_text = ", ".join(simple_perms)
            story.append(Paragraph(perms_text, cell_regular))
            story.append(Spacer(1, 10))
            
    elif filetype == 'image':
        story.append(make_heading("Embedded Image Channels", heading_style))
        qr_url = scan_data.get('qr_url')
        qr_status = qr_url if qr_url else "No QR codes detected inside the image frame."
        
        stego_status = "Steganography scanner checked raw binary image stream for hidden/appended URLs."
        
        img_rows = [
            [Paragraph("Vector", cell_bold), Paragraph("Analysis Result Details", cell_bold)],
            [Paragraph("QR Code URL Target", cell_regular), Paragraph(qr_status, cell_regular)],
            [Paragraph("Binary Stego Check", cell_regular), Paragraph(stego_status, cell_regular)]
        ]
        img_table = Table(img_rows, colWidths=[150, 354])
        img_styles = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ]
        for r_idx in range(1, len(img_rows)):
            bg = colors.HexColor('#f8fafc') if r_idx % 2 == 0 else colors.white
            img_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
            
        img_table.setStyle(TableStyle(img_styles))
        story.append(KeepTogether([img_table]))
        story.append(Spacer(1, 10))

    # 5. Extracted URLs Table
    url_scans = scan_data.get('url_scans', [])
    story.append(make_heading(f"Extracted Domains Security Audit ({len(url_scans)} domains analyzed)", heading_style))
    
    if url_scans:
        url_rows = [
            [Paragraph("Hardcoded Domain / URL", cell_bold), Paragraph("Verdict", cell_bold), Paragraph("Heuristics Triggered", cell_bold)]
        ]
        for u_scan in url_scans:
            u_url = u_scan.get('url', '')
            u_verdict = u_scan.get('verdict', 'Safe').upper()
            u_score = u_scan.get('score', 0)
            u_results = u_scan.get('results', [])
            
            triggered_sigs = []
            for sig in u_results:
                title = sig.get('name') or sig.get('title') or 'Triggered Check'
                triggered_sigs.append(title)
                
            sigs_text = ", ".join(triggered_sigs) if triggered_sigs else "Clean (No risk flags)"
            
            verdict_badge_color = colors.HexColor('#991b1b') if u_verdict == 'PHISHING' else (colors.HexColor('#c2410c') if u_verdict == 'SUSPICIOUS' else colors.HexColor('#065f46'))
            
            u_para = Paragraph(f"<font face='Courier-Bold' size='7'>{u_url}</font>", cell_regular)
            verdict_para = Paragraph(f"<font color='{verdict_badge_color.hexval()}'><b>{u_verdict}</b></font> ({u_score}/100)", cell_regular)
            sigs_para = Paragraph(sigs_text, cell_regular)
            
            url_rows.append([u_para, verdict_para, sigs_para])
            
        url_table = Table(url_rows, colWidths=[180, 120, 204])
        url_styles = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ]
        for r_idx in range(1, len(url_rows)):
            bg = colors.HexColor('#f8fafc') if r_idx % 2 == 0 else colors.white
            url_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
            
        url_table.setStyle(TableStyle(url_styles))
        story.append(KeepTogether([url_table]))
    else:
        no_urls_p = Paragraph("No embedded/extracted URL domains were found or parsed during sandbox decompilation.", cell_regular)
        story.append(no_urls_p)
        
    # 4. Checklist, Timeline & Recommendations
    story.extend(make_checklist_section(scan_data, heading_style, cell_bold, cell_regular))
    story.extend(make_timeline_section(scan_data, heading_style, cell_bold, cell_regular))
    story.extend(make_recommendations_section(verdict_text, score, heading_style, cell_regular))

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def generate_pdf(scan_data, logo_source="logo.png"):
    """
    Main entry point for report PDF generation.
    Checks the keys of the scan_data dictionary to identify the scan type
    (Email, File Sandbox, or Website URL) and delegates to the correct generator layout.
    """
    if 'sender_analysis' in scan_data:
        return generate_email_pdf(scan_data, logo_source)
    elif 'filetype' in scan_data:
        return generate_file_pdf(scan_data, logo_source)
    else:
        return generate_url_pdf(scan_data, logo_source)
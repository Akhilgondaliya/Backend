import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect, Polygon
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
        
        # Draw elegant page border
        self.setStrokeColor(colors.HexColor('#cbd5e1'))
        self.setLineWidth(1)
        self.rect(24, 24, 612 - 48, 792 - 48, fill=0, stroke=1)
        
        # Bottom Rule
        self.setStrokeColor(colors.HexColor('#d0e0ee'))
        self.setLineWidth(0.5)
        self.line(54, 52, 612 - 54, 52)
        
        # Footer Disclaimer & Page Counters
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor('#64748b'))
        self.drawString(54, 38, "Disclaimer: Developed as a hands-on cybersecurity research project.")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 38, page_text)
        
        self.restoreState()

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
    t = Table([[badge_p]], colWidths=[55], rowHeights=[14])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    return t

def make_shield_logo(width, height, color):
    """
    Generate a vector shield logo as a Flowable (Drawing).
    Matches the classic FiShield shape: flat top, curved sides, pointed bottom.
    """
    d = Drawing(width, height)
    w = width
    h = height
    # Classic shield: flat top, straight sides that angle inward to a bottom point
    pts = [
        0, h,                  # Top-left corner
        w, h,                  # Top-right corner
        w, h * 0.45,           # Right side drops straight down
        w / 2, 0,              # Bottom center point
        0, h * 0.45,           # Left side drops straight down
    ]
    shield = Polygon(pts, fillColor=color, strokeColor=None)
    d.add(shield)

    # Clean inner checkmark (tick mark)
    check_pts = [
        w * 0.22, h * 0.55,    # Start of check (left)
        w * 0.42, h * 0.30,    # Bottom of check (dip)
        w * 0.78, h * 0.75,    # End of check (right-top)
        w * 0.68, h * 0.80,    # Inner right-top
        w * 0.42, h * 0.45,    # Inner dip
        w * 0.30, h * 0.62,    # Inner left
    ]
    checkmark = Polygon(check_pts, fillColor=colors.white, strokeColor=None)
    d.add(checkmark)
    return d

def make_heading(text, heading_style):
    shield = make_shield_logo(10, 12, colors.HexColor('#2563eb'))
    t = Table([[shield, Paragraph(text, heading_style)]], colWidths=[16, 488])  # Total: 504
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('LINEBELOW', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')), # Sleek, soft slate rule under heading
    ]))
    t.spaceBefore = 12
    t.spaceAfter = 8
    return t

def make_risk_bar(score, bar_color):
    """
    Helper to generate a progress-bar visual for the risk score.
    """
    d = Drawing(140, 10)
    # Background Track (grey)
    d.add(Rect(0, 0, 140, 10, fillColor=colors.HexColor('#e2e8f0'), strokeColor=None, rx=3, ry=3))
    # Filled Portion
    fill_width = max(2, int(140 * (score / 100.0)))
    d.add(Rect(0, 0, fill_width, 10, fillColor=bar_color, strokeColor=None, rx=3, ry=3))
    return d

def generate_pdf(scan_data):
    """
    Generates a clean, single-page professional security audit PDF report
    styled to match premium, modern layout specifications.
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
        textColor=colors.HexColor('#1e3a8a'), # Premium Dark Blue Title
        alignment=0
    )
    
    meta_style = ParagraphStyle(
        'ReportMeta',
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#64748b'),
        alignment=0
    )
    
    heading_style = ParagraphStyle(
        'SectionHeading',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#1e293b'), # Dark slate section heading
        spaceAfter=0,
        spaceBefore=0
    )
    
    heading_style_no_block = ParagraphStyle(
        'SectionHeadingNoBlock',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=8,
        spaceBefore=12
    )
    
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#1e293b')
    )
    
    cell_regular = ParagraphStyle(
        'CellRegular',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#334155')
    )

    verdict_text = scan_data.get('verdict', 'Safe').upper()
    score = scan_data.get('score', 0)
    url = scan_data.get('url', 'N/A')
    
    # Colors matching threat level severities and soft dashboard callout panels
    if verdict_text == 'PHISHING':
        verdict_color = colors.HexColor('#be123c') # Crimson red
        verdict_bg = colors.HexColor('#fff1f2')    # Rose-50 bg
        verdict_label = "Likely Phishing"
        verdict_description = "CRITICAL THREAT: This URL exhibits strong patterns matching known phishing signatures, brand impersonations, or invalid security certificates. Do not interact with this page."
        recs = [
            ("DO NOT ENTER CREDENTIALS", "This domain exhibits strong phishing signatures. Never input passwords, credit cards, or personal data."),
            ("Perform Password Resets", "If you have already entered credentials on the scanned site, change the passwords for those services immediately."),
            ("Enable Multi-Factor Authentication", "Ensure MFA/2FA is active on all core accounts to prevent unauthorized access even if credentials were leaked."),
            ("Report Hostname to APWG", "Forward the malicious URL to anti-phishing networks (e.g. APWG, Google Safe Browsing) to aid active blocking.")
        ]
    elif verdict_text == 'SUSPICIOUS':
        verdict_color = colors.HexColor('#d97706') # Amber yellow
        verdict_bg = colors.HexColor('#fffbeb')    # Amber-50 bg
        verdict_label = "Suspicious Indicators"
        verdict_description = "WARNING: Potential risk indicators detected. The domain is young, lacks encryption, or contains suspicious subdomain depth. Proceed with caution."
        recs = [
            ("Verify Sender Identity", "If you received this URL via an unexpected message (email, SMS, social media), verify the sender's identity."),
            ("Inspect for Typosquatting", "Double check the hostname characters for look-alike characters (e.g., 'arnazon' instead of 'amazon')."),
            ("Avoid Financial Transactions", "Do not process any card payments or connect digital wallets on suspicious websites until verified."),
            ("Scan Local Machine", "Run a local anti-malware scan to ensure no drive-by scripts or cookies were downloaded.")
        ]
    else:
        verdict_color = colors.HexColor('#059669') # Emerald green
        verdict_bg = colors.HexColor('#f0fdf4')    # Green-50 bg
        verdict_label = "Clean / Safe"
        verdict_description = "SECURE: No threat indicators or malicious characteristics were detected. This site resolves correctly and uses valid encryption."
        recs = [
            ("Exercise Standard Caution", "Although this scan did not trigger indicators, always verify domains before inputting secure credentials."),
            ("Inspect Email headers", "If the URL originated from an email claiming to be from an official entity, inspect the sender domain details."),
            ("Keep Security Software Active", "Ensure browser built-in anti-phishing protection is enabled and active in your settings.")
        ]

    story = []

    # 1. Enterprise Header Panel (Navy background with white text and Report Details)
    header_left_style = ParagraphStyle(
        'HeaderLeft',
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#ffffff')
    )
    header_subtitle_style = ParagraphStyle(
        'HeaderSub',
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#94a3b8') # Slate-400
    )
    header_right_style = ParagraphStyle(
        'HeaderRight',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#3b82f6'), # Vibrant blue
        alignment=2 # Right aligned
    )
    header_meta_style = ParagraphStyle(
        'HeaderMeta',
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#94a3b8'),
        alignment=2
    )
    
    logo_text = "<b><font color='#3b82f6'>PHISH</font><font color='#ffffff'>ZERO</font></b>"
    p_logo = Paragraph(logo_text, header_left_style)
    p_sub = Paragraph("REAL-TIME THREAT INTELLIGENCE AUDIT", header_subtitle_style)
    
    # Subtable to align shield logo and text horizontally
    header_shield = make_shield_logo(20, 24, colors.HexColor('#3b82f6'))
    logo_sub_data = [[header_shield, p_logo]]
    logo_sub_table = Table(logo_sub_data, colWidths=[26, 294])
    logo_sub_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    
    report_id = f"PZ-{int(datetime.now().timestamp()) % 10000000:07d}"
    p_right = Paragraph("THREAT SECURITY REPORT", header_right_style)
    p_meta = Paragraph(f"Report ID: {report_id}<br/>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", header_meta_style)
    
    header_data = [
        [logo_sub_table, p_right],
        [p_sub, p_meta]
    ]
    header_table = Table(header_data, colWidths=[320, 184])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f172a')), # Deep navy/charcoal
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
        ('LINEBELOW', (0, 1), (-1, 1), 3, colors.HexColor('#3b82f6')), # Thick blue accent border bottom
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))

    # 2. Verdict callout panel (Dashboard-style widget with left accent border and risk gauge)
    v_title_style = ParagraphStyle(
        'VerdictTitle',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=verdict_color
    )
    v_desc_style = ParagraphStyle(
        'VerdictDesc',
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#475569') # Dark grey description
    )
    v_score_label_style = ParagraphStyle(
        'VerdictScoreLabel',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#475569'),
        alignment=1 # Centered
    )
    v_score_val_style = ParagraphStyle(
        'VerdictScoreVal',
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=verdict_color,
        alignment=1 # Centered
    )
    
    left_flowables = [
        Paragraph(f"AUDIT VERDICT: {verdict_label.upper()}", v_title_style),
        Spacer(1, 4),
        Paragraph(verdict_description, v_desc_style)
    ]
    
    right_flowables = [
        Paragraph("RISK SCORE", v_score_label_style),
        Spacer(1, 2),
        make_risk_bar(score, verdict_color),
        Spacer(1, 2),
        Paragraph(f"<b>{score}</b> <font size=8 color='#64748b'>/ 100</font>", v_score_val_style)
    ]
    
    verdict_table = Table([[left_flowables, right_flowables]], colWidths=[344, 160])  # Total: 504
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_bg),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBEFORE', (0, 0), (0, -1), 4, verdict_color), # Thick accent line on left
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (0, 0), 12),
        ('RIGHTPADDING', (-1, -1), (-1, -1), 12),
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    # 3. Accented Target URL Card
    url_label_style = ParagraphStyle(
        'UrlLabel',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#1e3a8a')
    )
    url_text_style = ParagraphStyle(
        'UrlText',
        fontName='Courier', # Monospace style for URL
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0f172a')
    )
    
    url_card_data = [[
        [
            Paragraph("ANALYZED TARGET URL", url_label_style),
            Spacer(1, 3),
            Paragraph(url, url_text_style)
        ]
    ]]
    url_card = Table(url_card_data, colWidths=[504])  # Total: 504
    url_card.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')), # Light slate-50
        ('LINEBEFORE', (0, 0), (0, -1), 3, colors.HexColor('#3b82f6')), # Blue left border
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')), # Thin border around
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(url_card)
    story.append(Spacer(1, 10))

    # 4. Risk Factors Detected Section
    story.append(make_heading("Risk Factors Detected", heading_style))
    
    results = scan_data.get('results', [])
    ssl_info = scan_data.get('ssl', {})
    whois_info = scan_data.get('whois', {})
    
    risk_rows = []
    
    # 1. Domain Resolution / Inactivity Heuristic
    domain_does_not_resolve = False
    if whois_info.get('error') or whois_info.get('age_days', 0) == 0 or whois_info.get('registrar', 'N/A') == 'N/A':
        domain_does_not_resolve = True
        
    if domain_does_not_resolve:
        badge = make_badge("CRITICAL", colors.HexColor('#be123c'))
        desc_p = Paragraph("<b>Domain Resolution Failed</b> — The hostname does not resolve to a valid IP address or is inactive.", cell_regular)
        risk_rows.append([badge, desc_p])
        
    # 2. Heuristic rules matching
    for sig in results:
        if sig.get('triggered'):
            name = sig.get('name')
            pts = sig.get('points', 0)
            
            if name == "No HTTPS":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                desc_p = Paragraph("<b>No HTTPS Connection</b> — Transmission is unencrypted and vulnerable to interception.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Suspicious TLD":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                extracted_domain = tldextract.extract(url)
                tld_name = f".{extracted_domain.suffix}" if extracted_domain.suffix else ".tk"
                desc_p = Paragraph(f"<b>Suspicious Top-Level Domain (TLD)</b> — The TLD ({tld_name}) is highly associated with phishing campaigns.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Phishing Keywords":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                from url_checker import PHISHING_KEYWORDS
                keywords_triggered = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
                keywords_str = ", ".join(keywords_triggered) if keywords_triggered else "login, verify, secure, account, confirm"
                desc_p = Paragraph(f"<b>Phishing Keywords Detected</b> — URL contains suspicious terms: {keywords_str}", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Hyphen in Domain":
                badge = make_badge("LOW", colors.HexColor('#4f46e5'))
                desc_p = Paragraph("<b>Hyphen in Domain Name</b> — Often used to spoof brand names (e.g., brand-security.com).", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Digits in Domain":
                badge = make_badge("LOW", colors.HexColor('#4f46e5'))
                desc_p = Paragraph("<b>Numeric Characters in Domain</b> — Hostname contains random numbers, typical of fake URLs.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Brand Impersonation":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                desc_p = Paragraph("<b>Brand Spoofing / Impersonation</b> — The domain contains names similar to popular targets.", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name not in ["IP as Host", "Shortener Domain", "Subdomain Depth", "URL Length", "Hex Encoding", "Double Slash"]:
                if pts >= 25:
                    badge = make_badge("CRITICAL", colors.HexColor('#be123c'))
                elif pts >= 15:
                    badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                elif pts >= 8:
                    badge = make_badge("MEDIUM", colors.HexColor('#d97706'))
                else:
                    badge = make_badge("LOW", colors.HexColor('#4f46e5'))
                desc_p = Paragraph(f"<b>{name}</b> — {sig.get('description', '')}", cell_regular)
                risk_rows.append([badge, desc_p])
                
    # 3. SSL issues
    if not domain_does_not_resolve:
        if not ssl_info.get('valid'):
            badge = make_badge("CRITICAL", colors.HexColor('#be123c'))
            desc_p = Paragraph("<b>Invalid/Missing SSL Certificate</b> — The site lacks a valid SSL certificate, indicating an insecure or fake connection.", cell_regular)
            risk_rows.append([badge, desc_p])
        elif ssl_info.get('warning'):
            badge = make_badge("HIGH", colors.HexColor('#ea580c'))
            desc_p = Paragraph(f"<b>Imminent SSL Expiration</b> — The SSL certificate is set to expire shortly ({ssl_info.get('days_left', 0)} days remaining).", cell_regular)
            risk_rows.append([badge, desc_p])
            
    if not risk_rows:
        badge = make_badge("CLEAN", colors.HexColor('#059669'))
        desc_p = Paragraph("No threat indicators or anomalous risk factors were triggered during this security audit.", cell_regular)
        risk_rows.append([badge, desc_p])
        
    risk_table = Table(risk_rows, colWidths=[65, 439])
    risk_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (1, 0), (1, -1), 8),
    ]))
    story.append(KeepTogether([risk_table]))
    story.append(Spacer(1, 10))

    # 5. Technical Analysis Section
    story.append(make_heading("Technical Metrics & Parameters", heading_style))
    
    url_len = f"{len(url)} characters"
    
    if url.lower().startswith('https://'):
        https_status = "<b><font color='#059669'>Yes (Encrypted)</font></b>"
    else:
        https_status = "<b><font color='#be123c'>No (Unencrypted)</font></b>"
    
    extracted = tldextract.extract(url)
    tld_val = f".{extracted.suffix}" if extracted.suffix else "None"
    
    subdomain_parts = [p for p in extracted.subdomain.split('.') if p]
    subdomain_depth = f"{len(subdomain_parts)} levels"
    if len(subdomain_parts) >= 3:
        subdomain_depth += " <font color='#ea580c'>(High)</font>"
    else:
        subdomain_depth += " <font color='#059669'>(Normal)</font>"
    
    from url_checker import PHISHING_KEYWORDS
    keywords_triggered = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
    if keywords_triggered:
        keywords_val = f"<b><font color='#be123c'>{len(keywords_triggered)} detected</font></b> ({', '.join(keywords_triggered[:3])})"
    else:
        keywords_val = "<font color='#059669'>0 detected</font>"
    
    if ssl_info.get('valid'):
        ssl_status = "<b><font color='#059669'>Valid Certificate</font></b>"
        ssl_expiry = f"{ssl_info.get('expiry_date', 'N/A')} ({ssl_info.get('days_left', 0)} days left)"
    else:
        ssl_status = "<b><font color='#be123c'>Invalid / None</font></b>"
        ssl_expiry = "<font color='#be123c'>N/A</font>"
    
    age_days = whois_info.get('age_days', 0)
    if age_days > 0:
        if age_days < 90:
            domain_age = f"<b><font color='#be123c'>{age_days} days (Young Site)</font></b>"
        else:
            domain_age = f"<font color='#059669'>{age_days} days (Established)</font>"
    else:
        domain_age = "<b><font color='#be123c'>N/A (Unregistered/No WHOIS)</font></b>"
        
    registrar_val = whois_info.get('registrar', 'N/A')
    if registrar_val == 'N/A':
        registrar_val = "<b><font color='#be123c'>Unknown / None</font></b>"
    
    tech_rows = [
        [Paragraph("<font color='white'><b>Metric Parameter</b></font>", cell_bold), Paragraph("<font color='white'><b>Observation / Value</b></font>", cell_bold)],
        [Paragraph("Target URL Length", cell_regular), Paragraph(url_len, cell_regular)],
        [Paragraph("HTTPS Encryption Status", cell_regular), Paragraph(https_status, cell_regular)],
        [Paragraph("Top-Level Domain (TLD)", cell_regular), Paragraph(tld_val, cell_regular)],
        [Paragraph("Subdomain Depth Levels", cell_regular), Paragraph(subdomain_depth, cell_regular)],
        [Paragraph("Phishing Keyword Hits", cell_regular), Paragraph(keywords_val, cell_regular)],
        [Paragraph("SSL Certificate Status", cell_regular), Paragraph(ssl_status, cell_regular)],
        [Paragraph("SSL Expiration Period", cell_regular), Paragraph(ssl_expiry, cell_regular)],
        [Paragraph("Registered Domain Age", cell_regular), Paragraph(domain_age, cell_regular)],
        [Paragraph("Domain Registrar Name", cell_regular), Paragraph(registrar_val, cell_regular)]
    ]
    
    tech_table = Table(tech_rows, colWidths=[200, 304])
    
    tech_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')), # Deep charcoal header
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')), # Clean grey borders
        ('LINEBEFORE', (1, 0), (1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]
    
    for r_idx in range(1, len(tech_rows)):
        bg = colors.HexColor('#f8fafc') if r_idx % 2 == 0 else colors.white # Alternating rows
        tech_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
        
    tech_table.setStyle(TableStyle(tech_styles))
    story.append(KeepTogether([tech_table]))
    story.append(Spacer(1, 10))

    # 6. Actionable Security Mitigation Plan
    story.append(make_heading("Actionable Security Mitigation Plan", heading_style))
    
    mitigation_rows = []
    num_style = ParagraphStyle(
        'MitNum',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
        alignment=1 # Centered
    )
    
    for idx, (m_title, m_desc) in enumerate(recs, 1):
        num_box = Table([[Paragraph(str(idx), num_style)]], colWidths=[14], rowHeights=[14])
        num_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#475569')), # Dark slate number box
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('PADDING', (0, 0), (-1, -1), 0),
        ]))
        
        desc_para = Paragraph(f"<b>{m_title}</b> — {m_desc}", cell_regular)
        mitigation_rows.append([num_box, desc_para])
        
    mitigation_table = Table(mitigation_rows, colWidths=[20, 484])
    mitigation_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(KeepTogether([mitigation_table]))

    # Build PDF using simple doc template
    doc.build(story, canvasmaker=NumberedCanvas)
    
    buffer.seek(0)
    return buffer.getvalue()

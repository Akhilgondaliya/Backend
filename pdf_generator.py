Detect Phishing! Before It's Too Late.import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, Image
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


def generate_pdf(scan_data, logo_source="logo.png"):
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

    story = []

    # 1. Header Hero Block (Asymmetric Two-Column Brand Layout)
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    meta_text = f"AUDIT TIMESTAMP: {date_str}  //  ENGINE: RUNTIME V1.0"
    
    title_text = "Phishing URL Analysis Report" if verdict_text == 'PHISHING' else "Website Security Analysis Report"
    
    # Left column content (Metadata and Text Title)
    left_content = [
        Paragraph(meta_text, meta_style),
        Spacer(1, 4),
        Paragraph(title_text, title_style)
    ]
    
    # Right column content (Logo image flowable)
    right_content = []
    try:
        # Scale logo to a clean aesthetic constraint (e.g., width=110, maintaining aspect ratio)
        logo_img = Image(logo_source, width=110, height=24)
        logo_img.hAlign = 'RIGHT'
        right_content.append(logo_img)
    except Exception:
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

    # Build Document Execution Flow
    doc.build(story, canvasmaker=NumberedCanvas)
    
    buffer.seek(0)
    return buffer.getvalue()
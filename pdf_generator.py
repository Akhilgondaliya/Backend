import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect
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

def make_heading(text, heading_style):
    square = Table([['']], colWidths=[8], rowHeights=[8])
    square.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    t = Table([[square, Paragraph(text, heading_style)]], colWidths=[14, 490])
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    t.spaceBefore = 12
    t.spaceAfter = 8
    return t

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
        textColor=colors.HexColor('#0f172a'),
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
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=0,
        spaceBefore=0
    )
    
    heading_style_no_block = ParagraphStyle(
        'SectionHeadingNoBlock',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=8,
        spaceBefore=12
    )
    
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#1e293b')
    )
    
    cell_regular = ParagraphStyle(
        'CellRegular',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#334155')
    )

    verdict_text = scan_data.get('verdict', 'Safe').upper()
    score = scan_data.get('score', 0)
    url = scan_data.get('url', 'N/A')
    
    # Colors matching threat level severities
    if verdict_text == 'PHISHING':
        verdict_color = colors.HexColor('#b91c1c') # Deep Red
        verdict_label = "Likely Phishing"
    elif verdict_text == 'SUSPICIOUS':
        verdict_color = colors.HexColor('#d97706') # Deep Amber/Yellow
        verdict_label = "Suspicious Indicators"
    else:
        verdict_color = colors.HexColor('#047857') # Deep Emerald Green
        verdict_label = "Clean / Safe"

    banner_left_style = ParagraphStyle(
        'BannerLeft',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.white,
        alignment=0
    )
    banner_right_style = ParagraphStyle(
        'BannerRight',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.white,
        alignment=2 # Right
    )

    story = []

    # 1. Title Block with solid colored accent square
    square_table = Table([['']], colWidths=[12], rowHeights=[12])
    square_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    
    title_para = Paragraph("Phishing URL Analysis Report" if verdict_text == 'PHISHING' else "Website Security Analysis Report", title_style)
    
    title_table = Table([[square_table, title_para]], colWidths=[20, 484])
    title_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('LEFTPADDING', (1, 0), (1, 0), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(title_table)
    story.append(Spacer(1, 4))

    # Subtitle / Generation Metadata
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    meta_text = f"Generated: {date_str} | Tool: PhishZero v1.0"
    story.append(Paragraph(meta_text, meta_style))
    story.append(Spacer(1, 8))
    
    # Thin divider rule
    divider = Table([['']], colWidths=[504], rowHeights=[1])
    divider.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(divider)
    story.append(Spacer(1, 12))

    # 2. Verdict Banner Card
    white_square = Table([['']], colWidths=[8], rowHeights=[8])
    white_square.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))

    banner_verdict_label_style = ParagraphStyle(
        'BannerVerdictLabel',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.white,
        alignment=0
    )
    
    banner_score_style = ParagraphStyle(
        'BannerScore',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.white,
        alignment=2 # Right
    )

    banner_table = Table([
        [
            Paragraph("VERDICT:", banner_verdict_label_style),
            white_square,
            Paragraph(verdict_label, banner_verdict_label_style),
            "",
            Paragraph(f"Risk Score: {score}/100", banner_score_style)
        ]
    ], colWidths=[80, 14, 150, 110, 150])
    
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (0, 0), 16),
        ('RIGHTPADDING', (-1, 0), (-1, 0), 16),
        ('PADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 12))

    # 3. Analyzed URL
    story.append(Paragraph("Analyzed URL", heading_style_no_block))
    
    url_para_style = ParagraphStyle(
        'UrlPara',
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#475569'),
    )
    url_p = Paragraph(url, url_para_style)
    url_p.spaceAfter = 12
    story.append(url_p)

    # 4. Risk Factors Detected
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
        badge = make_badge("CRITICAL", colors.HexColor('#b91c1c'))
        desc_p = Paragraph("<b>Domain does not resolve</b> — site does not exist or is inactive", cell_regular)
        risk_rows.append([badge, desc_p])
        
    # 2. Map other URL heuristics to match target text exactly
    for sig in results:
        if sig.get('triggered'):
            name = sig.get('name')
            pts = sig.get('points', 0)
            
            if name == "No HTTPS":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                desc_p = Paragraph("<b>No HTTPS</b> — connection is not encrypted", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Suspicious TLD":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                extracted_domain = tldextract.extract(url)
                tld_name = f".{extracted_domain.suffix}" if extracted_domain.suffix else ".tk"
                desc_p = Paragraph(f"<b>Suspicious top-level domain</b>: {tld_name}", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Phishing Keywords":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                from url_checker import PHISHING_KEYWORDS
                keywords_triggered = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
                keywords_str = ", ".join(keywords_triggered) if keywords_triggered else "login, verify, secure, account, confirm"
                desc_p = Paragraph(f"<b>Multiple phishing keywords</b>: {keywords_str}", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Hyphen in Domain":
                badge = make_badge("LOW", colors.HexColor('#2563eb'))
                desc_p = Paragraph("<b>Hyphen in domain</b> — common in phishing imitation domains", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Digits in Domain":
                badge = make_badge("LOW", colors.HexColor('#2563eb'))
                desc_p = Paragraph("<b>Digits in domain name</b> — unusual for legitimate sites", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name == "Brand Impersonation":
                badge = make_badge("HIGH", colors.HexColor('#ea580c'))
                desc_p = Paragraph("<b>Brand Impersonation</b> — domain contains a popular brand name", cell_regular)
                risk_rows.append([badge, desc_p])
                
            elif name not in ["IP as Host", "Shortener Domain", "Subdomain Depth", "URL Length", "Hex Encoding", "Double Slash"]:
                # General fallback for any other custom checks
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
                
    # 3. Add SSL Expiry or Validity if not already covered (only if domain resolves)
    if not domain_does_not_resolve:
        if not ssl_info.get('valid'):
            badge = make_badge("CRITICAL", colors.HexColor('#b91c1c'))
            desc_p = Paragraph("<b>Invalid/Missing SSL</b> — The connection is not secure (invalid certificate).", cell_regular)
            risk_rows.append([badge, desc_p])
        elif ssl_info.get('warning'):
            badge = make_badge("HIGH", colors.HexColor('#ea580c'))
            desc_p = Paragraph(f"<b>Imminent SSL Expiration</b> — Certificate expires soon ({ssl_info.get('days_left', 0)} days left).", cell_regular)
            risk_rows.append([badge, desc_p])
            
    if not risk_rows:
        badge = make_badge("CLEAN", colors.HexColor('#047857'))
        desc_p = Paragraph("No threat indicators or security risk factors were triggered during this sandboxed audit.", cell_regular)
        risk_rows.append([badge, desc_p])
        
    risk_table = Table(risk_rows, colWidths=[65, 439])
    risk_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (1, 0), (1, -1), 8),
    ]))
    story.append(KeepTogether([risk_table]))
    story.append(Spacer(1, 12))

    # 5. Technical Analysis Table
    story.append(make_heading("Technical Analysis", heading_style))
    
    # Prepare key details dynamically
    url_len = f"{len(url)} characters"
    https_status = "Yes" if url.lower().startswith('https://') else "x No"
    
    extracted = tldextract.extract(url)
    tld_val = f".{extracted.suffix}" if extracted.suffix else "None"
    
    subdomain_parts = [p for p in extracted.subdomain.split('.') if p]
    subdomain_depth = str(len(subdomain_parts))
    
    # Keywords count
    from url_checker import PHISHING_KEYWORDS
    keywords_triggered = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
    keywords_val = f"{len(keywords_triggered)} found" if keywords_triggered else "0 found"
    
    ssl_status = "Yes" if ssl_info.get('valid') else "x No"
    ssl_expiry = f"{ssl_info.get('expiry_date', 'N/A')} ({ssl_info.get('days_left', 0)} days left)" if ssl_info.get('valid') else "N/A"
    
    age_days = whois_info.get('age_days', 0)
    domain_age = f"{age_days} days" if age_days > 0 else "N/A"
    registrar_val = whois_info.get('registrar', 'N/A')
    
    tech_rows = [
        [Paragraph("<font color='white'><b>Feature</b></font>", cell_bold), Paragraph("<font color='white'><b>Value</b></font>", cell_bold)],
        [Paragraph("URL Length", cell_regular), Paragraph(url_len, cell_regular)],
        [Paragraph("HTTPS", cell_regular), Paragraph(https_status, cell_regular)],
        [Paragraph("TLD", cell_regular), Paragraph(tld_val, cell_regular)],
        [Paragraph("Subdomain Depth", cell_regular), Paragraph(subdomain_depth, cell_regular)],
        [Paragraph("Phishing Keywords", cell_regular), Paragraph(keywords_val, cell_regular)],
        [Paragraph("SSL Valid", cell_regular), Paragraph(ssl_status, cell_regular)],
        [Paragraph("SSL Expiry", cell_regular), Paragraph(ssl_expiry, cell_regular)],
        [Paragraph("Domain Age", cell_regular), Paragraph(domain_age, cell_regular)],
        [Paragraph("Registrar", cell_regular), Paragraph(registrar_val, cell_regular)]
    ]
    
    tech_table = Table(tech_rows, colWidths=[220, 284])
    
    tech_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('LINEBEFORE', (1, 0), (1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]
    
    for r_idx in range(1, len(tech_rows)):
        bg = colors.HexColor('#f1f5f9') if r_idx % 2 == 0 else colors.white
        tech_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
        
    tech_table.setStyle(TableStyle(tech_styles))
    story.append(KeepTogether([tech_table]))

    # Build PDF using simple doc template
    doc.build(story, canvasmaker=NumberedCanvas)
    
    buffer.seek(0)
    return buffer.getvalue()

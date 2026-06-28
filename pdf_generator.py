import io
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
import tldextract

class NumberedCanvas(canvas.Canvas):
    """
    Canvas to draw geometric borders and standard footers on all pages.
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
        self.rect(30, 30, 612 - 60, 792 - 60)
        
        # Bottom Rule above footer text
        self.setStrokeColor(colors.HexColor('#cbd5e1'))
        self.setLineWidth(0.5)
        self.line(44, 46, 612 - 44, 46)
        
        # Footer Disclaimer & Page Counters
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor('#94a3b8'))
        self.drawString(44, 32, "Disclaimer: Developed as a hands-on cybersecurity research project.")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 44, 32, page_text)
        
        self.restoreState()


def make_badge_compact(label, bg_color):
    """
    Helper to generate a cleanly styled colored rectangle badge flowable.
    """
    badge_style = ParagraphStyle(
        'BadgeTextCompact',
        fontName='Helvetica-Bold',
        fontSize=6.5,
        leading=8,
        textColor=colors.white,
        alignment=1 # Centered
    )
    badge_p = Paragraph(label, badge_style)
    t = Table([[badge_p]], colWidths=[50], rowHeights=[12])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
    ]))
    return t


def make_heading_compact(text, heading_style):
    """
    Creates a compact section header flowable with a colored accent bar.
    """
    accent_bar = Table([['']], colWidths=[3], rowHeights=[10])
    accent_bar.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#2563eb')), # Cyber Blue accent
        ('PADDING', (0, 0), (-1, -1), 0),
    ]))
    
    t = Table([[accent_bar, Paragraph(text, heading_style)]], colWidths=[8, 252])
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    t.spaceBefore = 4
    t.spaceAfter = 6
    return t


def build_single_page_pdf(scan_data, target_type, logo_source="logo.png"):
    """
    Builds a professional, clean single-page threat report PDF.
    target_type is one of: "URL", "EMAIL", "FILE"
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Text Styles
    title_style = ParagraphStyle(
        'ReportTitle',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.white,
        alignment=2 # Right
    )
    meta_style = ParagraphStyle(
        'ReportMeta',
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#38bdf8'), # cyan accent
        alignment=2 # Right
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=12,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=0,
        spaceBefore=0
    )
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0f172a')
    )
    cell_regular = ParagraphStyle(
        'CellRegular',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#334155')
    )
    
    # Context-aware color themes
    verdict_text = scan_data.get('verdict', 'Safe').upper()
    score = scan_data.get('score', 0)
    
    if verdict_text == 'PHISHING':
        verdict_color = colors.HexColor('#991b1b') # Crimson
        verdict_label = "CRITICAL: PHISHING THREAT DETECTED"
    elif verdict_text == 'SUSPICIOUS':
        verdict_color = colors.HexColor('#c2410c') # Rust Orange
        verdict_label = "WARNING: SUSPICIOUS ACTIVITY INDICATORS"
    else:
        verdict_color = colors.HexColor('#065f46') # Deep Green
        verdict_label = "VERDICT: CLEAN / UNCOMPROMISED"
        
    story = []
    
    # 1. Black Navbar Header
    # Load and scale Logo
    logo_img = None
    resolved_logo = logo_source
    if isinstance(logo_source, str) and logo_source:
        if not os.path.isabs(logo_source):
            resolved_logo = os.path.join(os.path.dirname(__file__), logo_source)
            
    if resolved_logo and ((isinstance(resolved_logo, str) and os.path.exists(resolved_logo)) or not isinstance(resolved_logo, str)):
        try:
            # Scale ratio is maintained based on original dimensions (1024x409) -> width 90, height 36
            logo_img = Image(resolved_logo, width=90, height=36)
            logo_img.hAlign = 'LEFT'
        except Exception:
            logo_img = None
            
    logo_container = []
    if logo_img:
        logo_container.append(logo_img)
    else:
        logo_fallback_style = ParagraphStyle(
            'LogoFallbackText',
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=colors.white
        )
        logo_container.append(Paragraph("Phish<font color='#38bdf8'>Zero</font>", logo_fallback_style))
        
    # Right side navbar text (Report Title & Timestamp)
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_title = "WEBSITE URL SECURITY REPORT"
    if target_type == "EMAIL":
        report_title = "EMAIL SECURITY ANALYSIS REPORT"
    elif target_type == "FILE":
        report_title = "FILE THREAT SANDBOX REPORT"
        
    navbar_right_p = [
        Paragraph(report_title, title_style),
        Spacer(1, 2),
        Paragraph(f"AUDIT DATE: {date_str}  //  PLATFORM CONSOLE", meta_style)
    ]
    
    navbar_table = Table([[logo_container, navbar_right_p]], colWidths=[130, 410])
    navbar_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0a0f1d')), # Dark Navy/Black Navbar
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
    ]))
    story.append(navbar_table)
    story.append(Spacer(1, 10))
    
    # 2. Verdict & Target Details Block (Side-by-side)
    target_value = ""
    if target_type == "URL":
        target_value = scan_data.get('url', 'N/A')
    elif target_type == "EMAIL":
        target_value = scan_data.get('sender_analysis', {}).get('email', 'N/A')
    elif target_type == "FILE":
        target_value = f"{scan_data.get('filename', 'Unknown File')}"
        
    target_label_style = ParagraphStyle(
        'TargetLabel',
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=2
    )
    target_val_style = ParagraphStyle(
        'TargetVal',
        fontName='Courier-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#0f172a')
    )
    
    target_left_cell = [
        Paragraph("AUDIT TARGET OBJECT", target_label_style),
        Paragraph(target_value, target_val_style)
    ]
    
    verdict_badge_style = ParagraphStyle(
        'VerdictBadgeText',
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=12,
        textColor=colors.white,
        alignment=1
    )
    verdict_score_style = ParagraphStyle(
        'VerdictScoreText',
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.white,
        alignment=1
    )
    
    target_right_cell = [
        Paragraph(verdict_label, verdict_badge_style),
        Spacer(1, 1),
        Paragraph(f"RISK INDEX: {score} / 100", verdict_score_style)
    ]
    
    details_table = Table([[target_left_cell, target_right_cell]], colWidths=[350, 190])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#f1f5f9')), # Light grey for target
        ('BACKGROUND', (1, 0), (1, 0), verdict_color), # Colored background for verdict
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('BORDER', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    story.append(details_table)
    story.append(Spacer(1, 6))
    
    # Risk progress bar
    width_active = max(1, score * 5.4)
    width_inactive = max(1, (100 - score) * 5.4)
    progress_table = Table([['', '']], colWidths=[width_active, width_inactive], rowHeights=[10])
    progress_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), verdict_color),
        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BORDER', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    story.append(progress_table)
    story.append(Spacer(1, 10))
    
    # 3. Main Split Body Grid (Identified Risk Signatures vs. Technical Metrics)
    # Columns: [260, 20, 260] (total 540 width)
    
    # Left Column: Risk Signatures
    left_side_flowables = []
    left_side_flowables.append(make_heading_compact("Identified Threat Signals", heading_style))
    
    risk_rows = []
    results = scan_data.get('results', [])
    ssl_info = scan_data.get('ssl', {})
    whois_info = scan_data.get('whois', {})
    
    triggered_rules = []
    if target_type == "URL":
        domain_resolve_fail = whois_info.get('error') or whois_info.get('age_days', 0) == 0 or whois_info.get('registrar', 'N/A') == 'N/A'
        if domain_resolve_fail:
            triggered_rules.append(("CRITICAL", "Domain resolution failure"))
        for sig in results:
            if sig.get('triggered'):
                name = sig.get('name')
                pts = sig.get('points', 0)
                sev = "LOW"
                if pts >= 25: sev = "CRITICAL"
                elif pts >= 15: sev = "HIGH"
                elif pts >= 8: sev = "MEDIUM"
                triggered_rules.append((sev, name))
        if not domain_resolve_fail and not ssl_info.get('valid'):
            triggered_rules.append(("CRITICAL", "Broken SSL/TLS Connection"))
            
    elif target_type == "EMAIL":
        sender = scan_data.get('sender_analysis', {})
        body = scan_data.get('body_analysis', {})
        links = scan_data.get('link_analysis', [])
        if sender.get('is_spoofed_brand'):
            triggered_rules.append(("CRITICAL", "Brand Identity Spoofing"))
        if sender.get('is_free_provider'):
            triggered_rules.append(("MEDIUM", "Public Free Mail Server"))
        if body.get('sensitive_info_requested'):
            triggered_rules.append(("HIGH", "Credential/PIN Request"))
        if body.get('urgency_count', 0) > 0:
            triggered_rules.append(("HIGH", "Urgent/Threatening Syntax"))
        if any(link.get('verdict') in ['Phishing', 'Suspicious'] for link in links):
            triggered_rules.append(("CRITICAL", "Phishing Target Link"))
            
    elif target_type == "FILE":
        file_type = scan_data.get('filetype', 'apk')
        high_risk = scan_data.get('high_risk_permissions', [])
        url_scans = scan_data.get('url_scans', [])
        stego = scan_data.get('stego_payload')
        
        if file_type == 'apk':
            if len(high_risk) > 0:
                triggered_rules.append(("CRITICAL", f"{len(high_risk)} High-Risk Permissions"))
            if any(u.get('verdict') in ['Phishing', 'Suspicious'] for u in url_scans):
                triggered_rules.append(("CRITICAL", "Malicious Link In APK Code"))
        else:
            if stego:
                triggered_rules.append(("CRITICAL", "Stego Payload Embedded"))
            if any(u.get('verdict') in ['Phishing', 'Suspicious'] for u in url_scans):
                triggered_rules.append(("CRITICAL", "Malicious QR Dest Link"))
                
    for sev, name in triggered_rules[:5]:
        bg_col = colors.HexColor('#2563eb')
        if sev == "CRITICAL": bg_col = colors.HexColor('#b91c1c')
        elif sev == "HIGH": bg_col = colors.HexColor('#ea580c')
        elif sev == "MEDIUM": bg_col = colors.HexColor('#d97706')
        
        badge = make_badge_compact(sev, bg_col)
        name_p = Paragraph(name, cell_regular)
        risk_rows.append([badge, name_p])
        
    if not risk_rows:
        badge = make_badge_compact("CLEAN", colors.HexColor('#047857'))
        desc_p = Paragraph("No critical threat vectors triggered during analysis.", cell_regular)
        risk_rows.append([badge, desc_p])
        
    risk_table = Table(risk_rows, colWidths=[55, 205])
    risk_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#f1f5f9')),
    ]))
    left_side_flowables.append(risk_table)
    
    # Right Column: Technical Metrics
    right_side_flowables = []
    right_side_flowables.append(make_heading_compact("Technical Audit Diagnostics", heading_style))
    
    tech_rows = []
    if target_type == "URL":
        tech_rows = [
            ("SSL Protocol Active", "HTTPS (Secure)" if target_value.lower().startswith('https://') else "HTTP (Insecure)"),
            ("SSL Status Indicator", "Valid Certificate" if ssl_info.get('valid') else "Invalid/Untrusted"),
            ("SSL Certificate Expiry", f"{ssl_info.get('days_left', 0)} days left" if ssl_info.get('valid') else "N/A"),
            ("Domain Age Baseline", f"{whois_info.get('age_days', 0)} days" if whois_info.get('age_days', 0) > 0 else "N/A"),
            ("Authoritative Registrar", whois_info.get('registrar', 'N/A')[:22]),
            ("Resolved IP Server", scan_data.get('ip_address', 'N/A'))
        ]
    elif target_type == "EMAIL":
        sender = scan_data.get('sender_analysis', {})
        body = scan_data.get('body_analysis', {})
        tech_rows = [
            ("Sender Domain Valid", sender.get('domain', 'N/A')[:22]),
            ("Free Server Flag", "Yes (Public Mail)" if sender.get('is_free_provider') else "No (Corporate/Auth)"),
            ("Impersonation Match", "Identity Spoof" if sender.get('is_spoofed_brand') else "Clean/Unspoofed"),
            ("Urgency Text Trigger", "Active Heuristics" if body.get('urgency_count', 0) > 0 else "No Urgency Signs"),
            ("Requests Private Info", "Credentials/Cards" if body.get('sensitive_info_requested') else "None Requested"),
            ("Spoofed Greeting Match", "Generic Header" if body.get('generic_greeting') else "Personalized")
        ]
    elif target_type == "FILE":
        file_type = scan_data.get('filetype', 'apk')
        filesize = scan_data.get('filesize', 0)
        high_risk = scan_data.get('high_risk_permissions', [])
        stego = scan_data.get('stego_payload')
        
        k = 1024
        sizes = ['Bytes', 'KB', 'MB', 'GB']
        import math
        i = 0 if filesize == 0 else int(math.floor(math.log(filesize) / math.log(k)))
        formatted_size = f"{round(filesize / (k ** i), 2)} {sizes[i]}" if filesize > 0 else "0 Bytes"
        
        if file_type == 'apk':
            tech_rows = [
                ("Binary Target Type", "Android Application Package (.apk)"),
                ("File Sandbox Size", formatted_size),
                ("High-Risk Permissions", f"{len(high_risk)} critical flags requested"),
                ("Manifest Security Code", "Audited & Decoded"),
                ("DEX Embedded URLs", f"{len(scan_data.get('url_scans', []))} links analyzed"),
                ("Threat Sandbox Status", "Execution Scan Terminated")
            ]
        else:
            tech_rows = [
                ("Binary Target Type", "Sandbox Image Vector"),
                ("File Sandbox Size", formatted_size),
                ("Steganography Audit", "Payload Attached" if stego else "Clean/No Stego"),
                ("QR Matrix Decoded", "Yes" if scan_data.get('qr_url') else "No QR Detected"),
                ("QR Dest Domain", scan_data.get('qr_url', 'N/A')[:22]),
                ("Threat Sandbox Status", "Decoding Check Complete")
            ]
            
    tech_table_data = []
    tech_table_data.append([Paragraph("Metric Vector", cell_bold), Paragraph("Observed State", cell_bold)])
    for label, val in tech_rows:
        tech_table_data.append([Paragraph(label, cell_regular), Paragraph(val[:32], cell_regular)])
        
    tech_table = Table(tech_table_data, colWidths=[120, 140])
    tech_table_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]
    for r_idx in range(1, len(tech_table_data)):
        bg = colors.HexColor('#f8fafc') if r_idx % 2 == 0 else colors.white
        tech_table_styles.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))
        
    tech_table.setStyle(TableStyle(tech_table_styles))
    right_side_flowables.append(tech_table)
    
    main_split_table = Table([[left_side_flowables, '', right_side_flowables]], colWidths=[260, 20, 260])
    main_split_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(main_split_table)
    story.append(Spacer(1, 10))
    
    # 4. Expert Recommendations Section
    recs = []
    if verdict_text == 'PHISHING':
        recs = [
            "<b>DO NOT ENTER PASSWORDS OR CREDENTIALS</b>: This target shows extreme indicators of credential harvesting.",
            "<b>ISOLATE & REPORT DESTINATION</b>: Mark the target malicious inside your console or client blacklists.",
            "<b>USE OFFICIAL CHANNELS ONLY</b>: Access official corporate bookmarked paths instead of external links."
        ]
    elif verdict_text == 'SUSPICIOUS':
        recs = [
            "<b>VERIFY ENCRYPTION LIFECYCLE</b>: Double-check SSL/TLS certificates and registrant details.",
            "<b>CONFIRM OUT-OF-BAND SENDER</b>: Reach out to the verified authority through official numbers/chats.",
            "<b>INSPECT FULL REDIRECT PATHS</b>: Review network requests triggered by scanning before sharing login data."
        ]
    else:
        recs = [
            "<b>CONTINUE ACTIVE MONITORING</b>: Although scanned as clean, remain cautious with unsolicited links/files.",
            "<b>KEEP WEB BROWSERS UPDATED</b>: Make sure the latest vendor security patches are running on host machines.",
            "<b>DEPLOY MULTI-FACTOR AUTH</b>: Maintain robust 2FA security levels for all critical target access points."
        ]
        
    rec_rows = []
    rec_rows.append([Paragraph("Expert Cyber Defense Recommendations", cell_bold)])
    for r in recs:
        bullet_text = f"<font color='#2563eb'>&#9656;</font> {r}"
        rec_rows.append([Paragraph(bullet_text, cell_regular)])
        
    rec_table = Table(rec_rows, colWidths=[540])
    rec_table_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('BORDER', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]
    rec_table.setStyle(TableStyle(rec_table_styles))
    story.append(rec_table)
    
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def generate_url_pdf(scan_data, logo_source="logo.png"):
    return build_single_page_pdf(scan_data, "URL", logo_source)


def generate_email_pdf(scan_data, logo_source="logo.png"):
    return build_single_page_pdf(scan_data, "EMAIL", logo_source)


def generate_file_pdf(scan_data, logo_source="logo.png"):
    return build_single_page_pdf(scan_data, "FILE", logo_source)


def generate_pdf(scan_data, logo_source="logo.png"):
    if 'sender_analysis' in scan_data:
        return build_single_page_pdf(scan_data, "EMAIL", logo_source)
    elif 'filetype' in scan_data:
        return build_single_page_pdf(scan_data, "FILE", logo_source)
    else:
        return build_single_page_pdf(scan_data, "URL", logo_source)
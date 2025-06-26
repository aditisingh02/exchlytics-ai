from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.linecharts import HorizontalLineChart
import io
import plotly.io as pio
import json
import os
from datetime import datetime

def create_pdf_report(report_data, output_path):
    """Generate a PDF report from the analysis data."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        spaceAfter=30
    )
    
    # Container for PDF elements
    elements = []
    
    # Title
    elements.append(Paragraph("Exchlytics AI Analysis Report", title_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Spacer(1, 20))
    
    # Summary Statistics
    elements.append(Paragraph("Summary Statistics", styles["Heading2"]))
    elements.append(Spacer(1, 12))
    
    # Create summary table
    summary_data = [
        ["Metric", "Value"],
        ["Total Packets", str(report_data.get('total_packets', 0))],
        ["TCP Retransmissions", str(len([err for err in report_data.get('errors', []) if err['type'] == 'TCP Retransmission']))],
    ]
    
    # Add latency statistics if available
    all_latencies_ms = [lat['latency_ms'] for lat in report_data.get('latencies', []) if 'latency_ms' in lat]
    if all_latencies_ms:
        avg_latency = sum(all_latencies_ms) / len(all_latencies_ms)
        min_latency = min(all_latencies_ms)
        max_latency = max(all_latencies_ms)
        summary_data.extend([
            ["Average Latency", f"{avg_latency:.2f} ms"],
            ["Minimum Latency", f"{min_latency:.2f} ms"],
            ["Maximum Latency", f"{max_latency:.2f} ms"]
        ])
    
    summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.aliceblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Error Analysis
    if report_data.get('errors'):
        elements.append(Paragraph("Error Analysis", styles["Heading2"]))
        elements.append(Spacer(1, 12))
        
        for i, err in enumerate(report_data['errors']):
            elements.append(Paragraph(f"Error {i+1}: {err['type']}", styles["Heading3"]))
            elements.append(Paragraph(f"Packet Sequence: {err['details'].get('seq', 'N/A')}", styles["Normal"]))
            if 'llm_response' in err:
                elements.append(Paragraph("AI Insight:", styles["Heading4"]))
                elements.append(Paragraph(err['llm_response'], styles["Normal"]))
            elements.append(Spacer(1, 12))
    
    # Latency Analysis
    if report_data.get('latencies'):
        elements.append(Paragraph("Latency Analysis", styles["Heading2"]))
        elements.append(Spacer(1, 12))
        
        latency_data = [["Session", "Latency (ms)"]]
        for i, lat in enumerate(report_data['latencies']):
            session_key = lat['session']
            formatted_session = f"{session_key[0]}:{session_key[1]} -> {session_key[2]}:{session_key[3]}"
            latency_data.append([formatted_session, f"{lat['latency_ms']:.2f}"])
        
        latency_table = Table(latency_data, colWidths=[4*inch, 2*inch])
        latency_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.aliceblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(latency_table)
    
    # Build the PDF
    doc.build(elements) 
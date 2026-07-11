from advanced_report import AdvancedReportGenerator
import os

db_path = "vulnerabilities.db"   # БД в текущей папке
generator = AdvancedReportGenerator(db_path, logo_path="logo.png")
generator.generate_pdf("report.pdf")
generator.generate_html("report.html")
print("PDF: report.pdf")
print("HTML: report.html")

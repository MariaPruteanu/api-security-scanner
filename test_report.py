from advanced_report import AdvancedReportGenerator

# Укажите путь к вашей БД (обычно vulnerabilities.db в папке проекта)
db_path = "vulnerabilities.db"   # или полный путь
generator = AdvancedReportGenerator(db_path, logo_path="logo.png")  # если лого нет – удалите параметр
generator.generate_pdf("scan_report_new.pdf")
generator.generate_html("scan_report_new.html")
print("Отчёты созданы: scan_report_new.pdf и scan_report_new.html")

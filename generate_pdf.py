from fpdf import FPDF

pdf = FPDF()
pdf.add_page()
pdf.set_auto_page_break(auto=True, margin=15)

pdf.set_font("Arial", 'B', 16)
pdf.cell(0, 10, "CVEDB Project Summary", ln=True, align='C')
pdf.ln(10)

pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "1. Project Overview", ln=True)
pdf.set_font("Arial", '', 11)
pdf.multi_cell(0, 8, "CVE Database (CVEDB) is a Python tool that stores and manages CVE data. "
                       "It supports both manual entry of vulnerabilities and bulk import from CSV/JSON files.")

pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "2. Tools & Technologies", ln=True)
pdf.set_font("Arial", '', 11)
pdf.multi_cell(0, 8, "- Python 3\n- SQLite\n- CSV & JSON parsing\n- OpenPyXL for XLSX export\n- venv for environment isolation")

pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "3. Features Implemented", ln=True)
pdf.set_font("Arial", '', 11)
pdf.multi_cell(0, 8, "- Manual CVE entry\n- Automatic import from CSV & JSON in the data folder\n- Search by CVE ID or vendor\n- View critical CVEs\n- Export to CSV and XLSX")

pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "4. Database Schema", ln=True)
pdf.set_font("Arial", '', 11)
pdf.multi_cell(0, 8, "CREATE TABLE cves (\n"
                       "    cve_id TEXT PRIMARY KEY,\n"
                       "    description TEXT,\n"
                       "    published_date TEXT,\n"
                       "    severity TEXT,\n"
                       "    cvss_score REAL,\n"
                       "    vendor TEXT,\n"
                       "    product TEXT\n"
                       ");")

pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "5. Sample Data", ln=True)
pdf.set_font("Arial", '', 11)
pdf.multi_cell(0, 8, "Sample files used:\n- data/cves_2016.csv\n- data/new_cves.json")

pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "6. Usage Instructions", ln=True)
pdf.set_font("Arial", '', 11)
pdf.multi_cell(0, 8, "1. Activate the virtual environment: .\\venv\\Scripts\\activate\n"
                       "2. Run: python main.py\n"
                       "3. Use the menu to add, view, or import CVEs")

pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "7. Challenges & Learnings", ln=True)
pdf.set_font("Arial", '', 11)
pdf.multi_cell(0, 8, "Handled both manual and automated imports, resolved database read/write permissions, "
                       "and ensured compatibility with CSV & NVD JSON formats.")

pdf.output("CVEDB_Project_Summary.pdf")
print("✅ PDF generated: CVEDB_Project_Summary.pdf")

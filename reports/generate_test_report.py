from pathlib import Path
import sys
sys.path.insert(0, '..\\src')
from basiliskscan.reporter import ReportGenerator
rg = ReportGenerator()
report_data = {
 'scan_metadata': {'tool':'BasiliskScan','version':'dev','scan_date':'','scan_timestamp':'now','target_path':'/tmp','output_file':'test-report.html','duration_seconds':12},
 'project_info':{'path':'/tmp','dependency_count':2,'ecosystems_found':{}},
 'dependencies':[{'name':'log4j-api','version':'2.17.1','ecosystem':'maven','declared_in':'pom.xml','vulnerabilities':[{'id':'CVE-2021-44228','severity':'CRITICAL','score':10.0,'description':'Remote Code Execution in log4j','fixed_version':'2.17.1'}]}],
 'vulnerabilities':{'log4j-api':[{'id':'CVE-2021-44228','severity':'CRITICAL','score':10.0,'description':'Remote Code Execution in log4j','fixed_version':'2.17.1'}]},
 'report_options':{}
}
html = rg.generate_html_report(report_data)
out = Path(__file__).parent / 'test-report.html'
out.write_text(html, encoding='utf-8')
print('WROTE', out)

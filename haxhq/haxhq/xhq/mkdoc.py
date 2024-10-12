import logging
import xlsxwriter
from docxtpl import DocxTemplate
from datetime import datetime
from inspect import currentframe, getframeinfo
from sys import path
from flask import Flask
from xhq.util import db_do, randstring
from xhq.reporting import get_report_data, get_report_data_by_host

app = Flask(__name__)
app.config.from_object('def_settings')
logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

def main():
    template_file, context = get_report_data()
    template = app.config['TEMPLATE_FOLDER'] + '/' + template_file
    doc = DocxTemplate(template)
    doc.render(context)
    doc.save('gen_doc.docx')

def create_report(user_id, reportby):
    result = {'success': False, 'error': None}
    filename = randstring(size=4, chset = 'letters') + '_draft_report.docx'
    result['filename'] = filename
    fullpath = app.config['REPORT_FOLDER'] + '/' + filename
    logger.debug('creating report as ' + filename)

    template_file, context = get_report_data(reportby)
    logger.debug('got report data')

    #logger.debug(repr(context))

    template = app.config['TEMPLATE_FOLDER'] + '/' + template_file
    try:
        doc = DocxTemplate(template)
        logger.debug('loaded template ' + template)
    except Exception as e:
        logger.error(repr(e))
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to load template ' + template_file)
        result['error'] = 'Failed to load template: ' + template_file
        return result

    try:
        doc.render(context)
        logger.debug('context parsed ok')
    except Exception as e:
        logger.error(repr(e))
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to load variables into template ' + template_file)
        result['error'] = 'Failed to load variables into template: ' + template_file
        return result

    try:
        doc.save(fullpath)
        logger.debug('report created ok')
    except Exception as e:
        logger.error(repr(e))
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to save report file')
        result['error'] = 'Failed to save report file as ' + fullpath
        return result


    logger.debug('setting report_done flag for engagement')
    qry = db_do('update engagements set report_done = true where user_id = %s and active is true', (user_id,))
    if not qry['success']:
        logger.error('query failed')

    result['success'] = True
    return result

def create_xlsx():
    logger.debug('exporting to xlsx')
    result = get_report_data_by_host()
    logger.debug('got report data by host')

    filename = randstring(size=4, chset = 'letters') + '_findings.xlsx'
    fullpath = app.config['REPORT_FOLDER'] + '/' + filename
    logger.debug('creating report as ' + filename)

    workbook = xlsxwriter.Workbook(fullpath)
    worksheet = workbook.add_worksheet()
    row = 0
    col = 0

    for label in ('IP', 'Hostname', 'Protocol', 'Port', 'Issue Name', 'Exposure', 'Severity', 'Description', 'Remediation'):
        worksheet.write(row, col, label)
        col += 1

    for entry in result:
        row += 1
        col = 0
        for item in entry:
            worksheet.write(row, col, item)
            col += 1

    workbook.close()
    logger.debug('xlsx file created')

    return filename

def create_xlsx_report(data):
    today = datetime.today().strftime('%d_%m_%Y')
    filename = 'int_report_' + today + '.xslx'
    fullpath = app.config['REPORT_FOLDER'] + '/' + filename
    logger.debug('creating report as ' + filename)

    workbook = xlsxwriter.Workbook(fullpath)
    worksheet = workbook.add_worksheet()
    bold = workbook.add_format({'bold': True})

    row = 0
    col = 0
    for label in ('Severity', 'Issue', 'Service', 'Remediation'):
        worksheet.write(row, col, label, bold)
        col += 1

    for entry in data:
        row += 1
        col = 0
        for item in entry.values():
            worksheet.write(row, col, item)
            col += 1

    workbook.close()
    logger.debug('xlsx file created')

    return filename


if __name__ == "__main__":
    main()


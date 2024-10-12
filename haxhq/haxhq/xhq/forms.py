import os
import logging
from sys import path
from datetime import date, timedelta
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, TextAreaField, IntegerField, SelectField, SubmitField, BooleanField, HiddenField, PasswordField, DecimalField
from wtforms.widgets import HiddenInput
from wtforms.validators import InputRequired, Email, Length, Optional, EqualTo, AnyOf, Regexp, NumberRange, IPAddress, URL

logger = logging.getLogger(__name__)
logger.setLevel('INFO')

dateregexp = '^[0-9/]{8,10}$'
name_regexp = "^[a-zA-Z0-9.'_():, -]{2,64}$"    # used for name, role, org_name
nickname_regexp = "^[0-9a-zA-Z._ -']{1,20}$"
phone_regexp = '^[0-9 +().-]{6,20}$'
hostname_regexp = '^[a-z][a-zA-Z0-9.-]{3,64}$'
protocol_regexp = '^[a-zA-Z]{2,12}$'
email_regexp = '^[a-z0-9\._\'-]{1,48}@[a-z0-9\.-]{4,48}$'

class NewEngagementForm(FlaskForm):
#    eid = IntegerField('eid', widget=HiddenInput())
    org_name = StringField('Organisation name', validators=[InputRequired(message='Please enter organisation name'),
                                                            Regexp(name_regexp)],
                                                render_kw={'class': 'validate reqd form_right'})
    target_subnets =  TextAreaField('Subnets in scope', validators=[Optional(), Regexp('^[0-9a-fA-F.:,\s/]{7,}$')],
                                    render_kw={'placeholder': '1.2.3.0/24, 4.3.2.1, 8.8.0.0/16', 'class': 'validate form_right'})
    target_urls =  TextAreaField('URLs in scope', validators=[Optional(), Regexp("^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;%=\s-]{4,}$")],
                                    render_kw={'placeholder': 'ab.ac.uk, test.cd.ac.uk/target', 'class': 'validate form_right'})
    eng_start = StringField('Engagement start', validators=[InputRequired(message='please enter engagement start date'),
                                                            Regexp(dateregexp)],
                                    render_kw={'placeholder': '22/02/2020', 'class': 'validate datepicker reqd form_right',
                                               'autocomplete': 'off'})
    eng_end = StringField('Engagement end', validators=[InputRequired(message='please enter engagement end date'),
                                                        Regexp(dateregexp)],
                                    render_kw={'placeholder': '27/02/2020', 'class': 'validate datepicker reqd form_right',
                                               'autocomplete': 'off'})
    contact1_name = StringField('Primary contact name', validators=[InputRequired(message='please enter primary contact name'),
                                                                    Regexp(name_regexp)],
                                                        render_kw={'class': 'validate reqd form_right'})
    contact1_role = StringField('Primary contact role', validators=[Optional(), Regexp(name_regexp)],
                                                        render_kw={'class': 'validate form_right'})
    contact1_email = StringField('Primary contact email', validators=[InputRequired(message='please enter primary contact email'),
                                                                      Regexp(email_regexp)],
                                                          render_kw={'class': 'validate reqd form_right'})
    contact1_phone = StringField('Primary contact phone', validators=[Optional(), Regexp(phone_regexp)],
                                                          render_kw={'class': 'validate form_right'})
    contact2_name = StringField('Secondary contact name', validators=[Optional(), Regexp(name_regexp)],
                                                          render_kw={'class': 'validate form_right secondary_contact hidden'})
    contact2_role = StringField('Secondary contact role', validators=[Optional(), Regexp(name_regexp)],
                                                          render_kw={'class': 'validate form_right secondary_contact hidden'})
    contact2_email = StringField('Secondary contact email', validators=[Optional(), Regexp(email_regexp)],
                                                            render_kw={'class': 'validate form_right secondary_contact hidden'})
    contact2_phone = StringField('Secondary contact phone', validators=[Optional(), Regexp(phone_regexp)],
                                                            render_kw={'class': 'validate form_right secondary_contact hidden'})
    #test_type = SelectField('Test type', choices=[], render_kw={'class': 'form_right'})
    test_type = SelectField('Test type', choices=[('pentest', 'Penetration test'), ('vulnscan', 'Vulnerability scan'),
                                                  ('audit', 'CSA (audit)')], validators=[AnyOf(['pentest', 'vulnscan', 'audit'])],
                                         render_kw={'class': 'form_right hidden', 'value': 'pentest'})
    submit = SubmitField('Create new engagement', render_kw={'class': 'button form_right green_btn'})

class AddHostForm(FlaskForm):
    ip0 = StringField('IP', validators=[InputRequired(message='please enter IP address'), IPAddress()],
                            render_kw={'class': 'validate reqd ip', 'placeholder': 'IP address'})
    hostname0 = StringField('FQDN', validators=[Optional(), Regexp(hostname_regexp, message='The allowed characters are: a-zA-Z0-9.-')],
                                    render_kw={'placeholder': 'hostname', 'class': 'validate hostname'})
    protocol0 = StringField('Protocol', validators=[InputRequired(message='please enter protocol'), Regexp(protocol_regexp)],
                                        render_kw={'class': 'validate reqd protocol', 'placeholder': 'tcp'})
    port0 = IntegerField('Port', validators=[InputRequired(message='please enter port'),
                                             NumberRange(min=0, max=65535, message='Port number must be between 0 and 65535')],
                                render_kw={'class': 'validate reqd port', 'placeholder': '80'})
    addhost = SubmitField('', render_kw={'value': 'Add host'})

class EditIssueForm(FlaskForm):
    name = TextAreaField('Title', validators=[InputRequired(message='Please enter the issue title'), Length(3,255)],
                                 render_kw={'autocomplete': 'off', 'class': 'validate reqd'})
    exposure = HiddenField('', validators=[AnyOf(['internal', 'external', 'adreview'])])
    severity = SelectField('Severity', validators=[AnyOf(['0','1','2','3','4'])],
                           choices=[('4','critical'),('3','high'),('2','medium'),('1','low'),('0','info')],
                           render_kw={'class': 'button'})
    cvss3 = DecimalField('CVSSv3', validators=[Optional(), NumberRange(min=0, max=10)], render_kw={'class': 'button cvss'})
    description = TextAreaField('Description', validators=[InputRequired(message='Please enter description')],
                                               render_kw={'class': 'validate largetext reqd'})
    details = TextAreaField('Details', validators=[Optional()], render_kw={'class': 'largetext'})
    discoverability = TextAreaField('Discoverability', validators=[Optional()])
    exploitability = TextAreaField('Exploitability', validators=[Optional()])
    impact = TextAreaField('Impact', validators=[Optional()])
    remediation = TextAreaField('Remediation', validators=[InputRequired(message='Please enter remediation')],
                                               render_kw={'class': 'validate largetext reqd'})
    cvss3_vector = HiddenField('', validators=[Optional(), Regexp('^[a-zA-Z0-9:.\/_#]{32,44}$')])
    iid = HiddenField('', validators=[Optional(), Regexp('^\d+$')])

class AddIssueForm(FlaskForm):
    name = TextAreaField('Title', validators=[InputRequired(message='Please enter the issue title'), Length(3,255)],
                                 render_kw={'autocomplete': 'off', 'class': 'validate reqd'})
    exposure = SelectField('Exposure', validators=[InputRequired(message='Please select exposure'),
                                                   AnyOf(['internal', 'external', 'adreview'])],
                                       choices=[('selectexp','-- select exposure --'),('external','external'),('internal','internal'),
                                                ('adreview','adreview')],
                                       render_kw={'class': 'button reqd validate'})
    severity = SelectField('Severity', validators=[AnyOf(['0','1','2','3','4'])],
                           choices=[('4','critical'),('3','high'),('2','medium'),('1','low'),('0','info')],
                           render_kw={'class': 'button'})
    cvss3 = DecimalField('CVSSv3', validators=[Optional(), NumberRange(min=0, max=10)], render_kw={'class': 'button cvss'})
    description = TextAreaField('Description', validators=[InputRequired(message='Please enter description')],
                                               render_kw={'class': 'validate largetext reqd'})
    details = TextAreaField('Details', validators=[Optional()], render_kw={'class': 'largetext'})
    discoverability = TextAreaField('Discoverability', validators=[Optional()])
    exploitability = TextAreaField('Exploitability', validators=[Optional()])
    impact = TextAreaField('Impact', validators=[Optional()])
    remediation = TextAreaField('Remediation', validators=[InputRequired(message='Please enter remediation')],
                                               render_kw={'class': 'validate largetext reqd'})
    cvss3_vector = HiddenField('', validators=[Optional(), Regexp('^[a-zA-Z0-9:.\/_#]{32,44}$')])

class EditCSAIssueForm(FlaskForm):
    name = TextAreaField('Title', validators=[InputRequired(message='Please enter title'), Length(3,255)],
                                 render_kw={'autocomplete': 'off', 'class': 'validate reqd form_right'})
    compliance = StringField('Compliance', validators=[InputRequired(message='Please enter compliance'),
                                                       AnyOf('FAILED','PASSED','WARNING')],
                                           render_kw={'placeholder': 'FAILED/PASSED/WARNING', 'class': 'validate reqd form_right'})
    description = TextAreaField('Description', validators=[InputRequired(message='Please enter description')],
                                               render_kw={'class': 'validate largetext reqd form_right'})
    rationale = TextAreaField('Rationale', validators=[Optional()], render_kw={'class': 'form_right'})
    impact = TextAreaField('Impact', validators=[Optional()], render_kw={'class': 'form_right'})
    remediation = TextAreaField('Remediation', validators=[InputRequired(message='Please enter remediation')],
                                               render_kw={'class': 'validate largetext reqd form_right'})
    reference = TextAreaField('References', validators=[Optional()], render_kw={'class': 'form_right'})
    iid = HiddenField('', validators=[Optional(), Regexp('^\d+$')])

class FileUploadForm(FlaskForm):
    scanfile = FileField(validators=[FileRequired()], render_kw={'multiple': 'multiple', 'class': 'fileupload'})
    scantype = SelectField('Scan type', validators=[AnyOf(['internal', 'external'])],
                           choices=[('external','external'), ('internal','internal')], render_kw={'class': 'button'} )
    submit = SubmitField('Import scans', render_kw={'class': 'button green_btn'})

class HostFilterForm(FlaskForm):
    host = StringField(validators=[Optional(), Regexp('^[a-zA-Z0-9 |:.-]{1,64}$')],
                       render_kw={'autocomplete': 'off', 'placeholder': 'IP/hostname', 'class': 'filter'})
    port = StringField(validators=[Optional(), Regexp('^[a-zA-Z0-9\/\* ]{1,10}$')],
                       render_kw={'autocomplete': 'off', 'placeholder': 'port', 'class': 'filter'})
    service = StringField(validators=[Optional(), Regexp('^[a-zA-Z0-9\*\?|_ -]{1,42}$')],
                       render_kw={'autocomplete': 'off', 'placeholder': 'service', 'class': 'filter optfld'})
    software = StringField(validators=[Optional(), Regexp('^[a-zA-Z0-9\*\?|\(\)\/\._ -]{1,42}$')],
                       render_kw={'autocomplete': 'off', 'placeholder': 'software', 'class': 'filter optfld'})
    findings = StringField(validators=[Optional(), Regexp('^[a-zA-Z\* ]{1,42}$')],
                       render_kw={'autocomplete': 'off', 'placeholder': 'severity', 'class': 'filter'})

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Regexp(email_regexp)], render_kw={'placeholder': 'Email address'} )
    password = PasswordField('Password', validators=[InputRequired()], render_kw={'placeholder': 'Password', 'autocomplete': 'off'} )
    submit = SubmitField('Login', render_kw={'class': 'green_btn'})

class SetPassForm(FlaskForm):
    password1 = PasswordField('New password', validators=[InputRequired()],
                                             render_kw={'placeholder': 'New password', 'autocomplete': 'off'} )
    password2 = PasswordField('Repeat password', validators=[InputRequired()],
                                                 render_kw={'placeholder': 'Repeat password', 'autocomplete': 'off'} )
    submit = SubmitField('Save', render_kw={'class': 'button green_btn'})

class UpdatePassForm(FlaskForm):
    password = PasswordField(validators=[InputRequired()], render_kw={'placeholder': 'Current password', 'autocomplete': 'off'} )
    password1 = PasswordField(validators=[InputRequired()], render_kw={'placeholder': 'New password', 'autocomplete': 'off'} )
    password2 = PasswordField(validators=[InputRequired()], render_kw={'placeholder': 'Repeat password', 'autocomplete': 'off'} )
    submit = SubmitField('Save', render_kw={'class': 'button green_btn'})

class UpdateNicknameForm(FlaskForm):
    nickname = StringField('Nickname', validators=[InputRequired(), Regexp(nickname_regexp)],
                           render_kw={'placeholder': 'nickname', 'class': 'validate'})
    submit = SubmitField('Save', render_kw={'class': 'right button green_btn'})

class ResetPassForm(FlaskForm):
    user = StringField('User', validators=[InputRequired(), Email()],
                       render_kw={'placeholder': 'Email address', 'class': 'validate'} )
    submit = SubmitField('Send password reset email', render_kw={'class': 'green_btn'})

# used to generate csrf token for merging issues
class DummyForm(FlaskForm):
    submit = SubmitField('Reset')

class StatsForm(FlaskForm):
    today = date.today()
    last_year = today - timedelta(days=365)
    todaystr = today.strftime("%d/%m/%Y")
    lastyearstr = last_year.strftime("%d/%m/%Y")

    title = StringField('Title', render_kw={'autocomplete': 'off', 'class':'filter', 'placeholder':'Search by issue title'})
    exposure = SelectField('Exposure', choices=[('external','external'), ('internal','internal'), ('all','all')],
                                       render_kw={'class':'filter'})
    stat_from = StringField('From', validators = [Regexp(dateregexp)],
                            render_kw={'class': 'validate datepicker filter', 'autocomplete': 'off',
                                               'placeholder': lastyearstr})
    stat_to = StringField('To', validators = [Regexp(dateregexp)],
                          render_kw={'class': 'validate datepicker filter', 'autocomplete': 'off',
                                           'placeholder': todaystr})
    results = SelectField('Results', choices=[('100','100'), ('200','200'), ('500','500'), ('all','all')],
                                     render_kw={'class':'filter'})
    orderby = SelectField('Sort', choices=[('severity','severity'), ('host_count','host_count'), ('member_count','member_count'),
                                           ('title','title')], render_kw={'class':'filter'})
    submit = SubmitField('Submit', render_kw={'id':'apply_filter'})

class LibSearchForm(FlaskForm):
    libsearchstr = StringField('Search', render_kw={'type': 'search', 'autocomplete': 'off',
                                              'placeholder':'Search by issue title or scanner'})
    libsearchtype = SelectField('Entry type', validators=[AnyOf(['all', 'manual', 'nessus', 'acunetix',
                                                                 'burp', 'qualys', 'pingcastle'])],
                                choices=[('all','all'), ('external','external'), ('internal','internal'), ('manual','custom'),
                                         ('nessus','nessus'), ('acunetix','acunetix'), ('burp','burp'), ('qualys','qualys'),
                                         ('pingcastle','pingcastle')])

class MfaCheckForm(FlaskForm):
    otp_code = StringField('OTP code', validators=[InputRequired(message='please enter otp code'), Regexp('^[0-9]{6}$')],
                                       render_kw={'autocomplete': 'off', 'class': 'validate left', 'placeholder': 'OTP code'})
    submit = SubmitField('Submit', render_kw={'class': 'green_btn right', 'style': 'width: 120px'})

class ReportsForm(FlaskForm):
    rep_from = StringField('From', validators = [Regexp(dateregexp)],
                           render_kw={'class': 'validate datepicker filter', 'autocomplete': 'off'})
    rep_to = StringField('To', validators = [Regexp(dateregexp)],
                         render_kw={'class': 'validate datepicker filter', 'autocomplete': 'off'})
    submit = SubmitField('Generate report', render_kw={'class': 'green_btn'})

class AddUserForm(FlaskForm):
    user_id = StringField('User ID', validators=[Optional(), Regexp("^[0-9]{1,2}$")],
                          render_kw={'class': 'uiclr disabled', 'readonly': 'true'})
    email = StringField('Email', validators=[InputRequired(message='please enter email address'), Regexp(email_regexp)],
                            render_kw={'placeholder': 'john.smith@acme.com', 'class': 'validate uiclr'} )
    name = StringField('Name', validators=[InputRequired(message="Please enter the user's name"), Regexp("^[A-Za-z', .-]{1,42}$")],
                            render_kw={'placeholder': 'John', 'class': 'validate uiclr'})
    surname = StringField('Surname', validators=[InputRequired(message="Please enter the user's surname"),
                                                 Regexp("^[A-Za-z', .-]{1,42}$")],
                            render_kw={'placeholder': 'Smith', 'class': 'validate uiclr'})
    nickname = StringField('Nickname', validators=[InputRequired(message="Please enter the user's nickname"),
                                                   Regexp(nickname_regexp)],
                            render_kw={'placeholder': 'zeus', 'class': 'validate uiclr'})
    phone = StringField('Phone', validators=[Optional(), Regexp(phone_regexp)],
                        render_kw={'placeholder': '020 1234 5678', 'class': 'validate uiclr'})
    user_type = StringField('Job title', validators=[InputRequired(message="Please enter the user's job title"),
                                                     Regexp(name_regexp)],
                                         render_kw={'placeholder': 'Penetration Tester', 'class': 'validate uiclr'} )
    user_group = SelectField('User group', validators=[InputRequired(), AnyOf(['hackers','managers','auditors'])],
                             choices=[('hackers','hackers')])
    admin = BooleanField('Admin', validators=[AnyOf([True, False])])
    disabled = BooleanField('Disabled', validators=[AnyOf([True, False])])
    submit = SubmitField('Save', render_kw={'class': 'button green_btn'})

class TemplateUploadForm(FlaskForm):
    template_type = SelectField('Template type', validators=[InputRequired(), AnyOf(['pentest','vulnscan','audit'])],
                                render_kw={'class': 'template-item'},
                                choices=[('pentest','penetration test')])
                                #choices=[('','-- select template type --'),('pentest','penetration test'),
                                #         ('vulnscan','vulnerability scan'),('audit','security audit')])
    template_file = FileField('Template file', validators=[FileRequired()], render_kw={'class': 'fileupload template-item'})
    submit = SubmitField('Update', render_kw={'class': 'button green_btn adminbtn'})

class TemplateDownloadForm(FlaskForm):
    template_type = SelectField('Template type', validators=[InputRequired(), AnyOf(['pentest','vulnscan','audit'])],
                                render_kw={'class': 'template-item'},
                                choices=[('pentest','penetration test')])
                                #choices=[('','-- select template type --'),('pentest','penetration test'),
                                #         ('vulnscan','vulnerability scan'),('audit','security audit')])
    template_version = SelectField('', validators=[InputRequired(), AnyOf(['current', 'default'])],
                                   render_kw={'class': 'template-item'},
                                   choices=[('','-- select template version --'), ('current','current'), ('default','haxhq default')])
    submit = SubmitField('Download', render_kw={'class': 'button green_btn adminbtn'})

class LogoUploadForm(FlaskForm):
    logo_file = FileField('Logo file', validators=[FileRequired()], render_kw={'class': 'fileupload template-item'})
    submit = SubmitField('Update', render_kw={'class': 'button green_btn adminbtn'})

def get_form(category, obj=None):
    logger.debug(repr(obj))
    catdict = { 'new_engagement': {'form': NewEngagementForm(obj=obj)},
                'upload_file':    {'form': FileUploadForm()},
                'edit_issue':     {'form': EditIssueForm(obj=obj)},
                'add_issue':      {'form': AddIssueForm(obj=obj)},
                'edit_csa_issue': {'form': EditCSAIssueForm(obj=obj)},
                'login':          {'form': LoginForm(obj=obj)},
                'reset_pass':     {'form': ResetPassForm(obj=obj)},
                'set_pass':       {'form': SetPassForm(obj=obj)},
                'update_pass':    {'form': UpdatePassForm(obj=obj)},
                'update_nickname':{'form': UpdateNicknameForm(obj=obj)},
                'add_host':       {'form': AddHostForm(obj=obj)},
                'dummy':          {'form': DummyForm(obj=obj)},
                'stats':          {'form': StatsForm(obj=obj)},
                '2fa_check':      {'form': MfaCheckForm(obj=obj)},
                'libsearch':      {'form': LibSearchForm(obj=obj)},
                'reports':        {'form': ReportsForm(obj=obj)},
                'adduser':        {'form': AddUserForm(obj=obj)},
                'update_logo':    {'form': LogoUploadForm(obj=obj)},
                'set_template':   {'form': TemplateUploadForm(obj=obj)},
                'get_template':   {'form': TemplateDownloadForm(obj=obj)},
                'hostfilter':     {'form': HostFilterForm(obj=obj)},
                #'contact':        {'form': ContactForm(obj=obj)},
              }
    if category in catdict:
        form = catdict[category]['form']
        return form
    else:
        logger.warn('bad category in request: ' + category)
        return False

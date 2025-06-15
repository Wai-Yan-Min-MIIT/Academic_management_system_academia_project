from django import forms
from academia.models import *


class StudentForm(forms.ModelForm):
    email = forms.EmailField(label="Email")

    class Meta:
        model = Student
        fields = [
            'StudentName', 'Salutation', 'DisciplineID', 'ProgramID', 'BatchID', 'SectionName',
            'RollNumber', 'StudentNRC', 'StudentPhone', 'StudentDOB', 'FatherName',
            'FatherNRC', 'FatherPhoneNumber', 'MotherName', 'MotherNRC', 'MotherPhoneNumber',
            'Address'
        ]
        widgets = {
            'StudentDOB': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        super(StudentForm, self).__init__(*args, **kwargs)
        self.fields['ProgramID'].queryset = Program.objects.all()
        self.fields['ProgramID'].label_from_instance = lambda obj: f"{obj.ProgramFullName}"
        self.fields['ProgramID'].empty_label = "Select Program"

        self.fields['BatchID'].queryset = Batch.objects.all()
        self.fields['BatchID'].label_from_instance = lambda obj: f"{obj.BatchYear}"
        self.fields['BatchID'].empty_label = "Select Batch Year"

        self.fields['DisciplineID'].queryset = Discipline.objects.all()
        self.fields['DisciplineID'].label_from_instance = lambda obj: f"{obj.DisciplineFullName}"
        self.fields['DisciplineID'].empty_label = "Select Discipline"

class BulkRegistrationForm(forms.Form):
    excel_file = forms.FileField(
        label='Upload Excel File',
        help_text='Accepted formats: .xlsx, .xls',
        widget=forms.ClearableFileInput(attrs={'class': 'form-control'})
    )


class FacultyStaffForm(forms.ModelForm):
    email = forms.EmailField(label="Email")

    SALUTATION_CHOICES = [
        ('Dr.', 'Dr.'),
        ('Daw', 'Daw'),
        ('Prof.', 'Prof.'),
        ('U', 'U'),
        ('Ma', 'Ma'),
        ('Mg', 'Mg'),
        ('Mr.', 'Mr.'),
        ('Mrs.', 'Mrs.'),
    ]

    DESIGNATION_CHOICES = [
        ('Lecturer', 'Lecturer'),
        ('Professor', 'Professor'),
        ('Tutor', 'Tutor'),
        ('lecture', 'lecture'),
        ('Assistant Lecturer', 'Assistant Lecturer'),
        ('Associate Professor', 'Associate Professor'),
        ('Rector', 'Rector'),
        ('Pro-Rector', 'Pro-Rector'),
        ('Head of Department', 'Head of Department'),
        ('Head of Division', 'Head of Division'),
        ('Head of Office', 'Head of Office'),
        ('Library Assistant', 'Library Assistant'),
        ('Doctor', 'Doctor'),
        ('Junior Clerk', 'Junior Clerk'),
        ('Nurse', 'Nurse'),
        ('Accountant', 'Accountant'),
        ('Registrar', 'Registrar'),
    ]

    DEPARTMENT_CHOICES = [
        ('Faculty of Computer Science', 'Faculty of Computer Science'),
        ('Faculty of Computing', 'Faculty of Computing'),
        ('Faculty of Computer Systems and Technologies', 'Faculty of Computer Systems and Technologies'),
        ('Department of English', 'Department of English'),
        ('Faculty of Information Science', 'Faculty of Information Science'),
        ('Department of Natural Science', 'Department of Natural Science'),
        ('Information Technology Supporting and Maintenance', 'Information Technology Supporting and Maintenance'),
        ('Department of Myanmar', 'Department of Myanmar'),
        ('Information Technology Support and Maintenance', 'Information Technology Support and Maintenance'),
        ('Management', 'Management'),
        ('Administration', 'Administration'),
        ('Student Affair', 'Student Affair'),
        ('Finance', 'Finance'),
        ('Library', 'Library'),
        ('External-IIITB', 'External-IIITB'),
        ('From UCSM', 'From UCSM'),
        ('IITB', 'IITB'),
    ]

    Salutation = forms.ChoiceField(choices=SALUTATION_CHOICES, label="Salutation")
    Designation = forms.ChoiceField(choices=DESIGNATION_CHOICES, label="Designation")
    Department = forms.ChoiceField(choices=DEPARTMENT_CHOICES, label="Department")

    class Meta:
        model = FacultyStaff
        fields = [
            'FacultyStaffName', 'ShortName', 'Salutation', 'Designation', 'Department',
            'NRC', 'Phone', 'Address'
        ]


class NotificationPreferencesForm(forms.ModelForm):
    class Meta:
        model = NotificationPreference
        fields = [
            'grades_alert',
            'attendance_alert', 
            'exam_schedule_alert',
            'institutional_announcement_alert',
            'event_notification_alert',
            'news_alert'
        ]
        widgets = {
            'grades_alert': forms.CheckboxInput(attrs={'class': 'sr-only', 'id': 'grades_alert'}),
            'attendance_alert': forms.CheckboxInput(attrs={'class': 'sr-only', 'id': 'attendance_alert'}),
            'exam_schedule_alert': forms.CheckboxInput(attrs={'class': 'sr-only', 'id': 'exam_schedule_alert'}),
            'institutional_announcement_alert': forms.CheckboxInput(attrs={'class': 'sr-only', 'id': 'institutional_announcement_alert'}),
            'event_notification_alert': forms.CheckboxInput(attrs={'class': 'sr-only', 'id': 'event_notification_alert'}),
            'news_alert': forms.CheckboxInput(attrs={'class': 'sr-only', 'id': 'news_alert'}),
        }


class SemesterForm(forms.ModelForm):
    SEMESTER_STATUS_CHOICES = [
        ('New', 'New'),
        ('Completed', 'Completed'),
        ('Current', 'Current'),
        ('Not Offered', 'Not Offered'),
    ]
    
    SemesterStatus = forms.ChoiceField(choices=SEMESTER_STATUS_CHOICES)

    class Meta:
        model = Semester
        fields = ['AY_ID', 'ProgramID', 'SemesterStatus', 'SemesterStartDate', 'SemesterEndDate', 'SemesterDescription']
        widgets = {
            'SemesterStartDate': forms.DateInput(attrs={'type': 'date'}),
            'SemesterEndDate': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        super(SemesterForm, self).__init__(*args, **kwargs)
        self.fields['ProgramID'].queryset = Program.objects.all()
        self.fields['ProgramID'].label_from_instance = lambda obj: f"{obj.ProgramFullName}"
        self.fields['ProgramID'].empty_label = None

class ProjectProposalForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['ProjectTitle', 'ProjectCredits', 'NumberStudents', 'ProgramID', 'ProjectType', 'ProjectSummary', 'Remarks']
        widgets = {
            'ProjectType': forms.Select(choices=[(1, 'Special Project'), (2, 'Capstone Project')]),
        }

    def __init__(self, *args, **kwargs):
        super(ProjectProposalForm, self).__init__(*args, **kwargs)
        self.fields['ProgramID'].queryset = Program.objects.all()
        self.fields['ProgramID'].label_from_instance = lambda obj: f"{obj.ProgramFullName}"
        self.fields['ProgramID'].empty_label = "Select Program"

class DisciplineForm(forms.ModelForm):
    class Meta:
        model = Discipline
        fields = ['DisciplineFullName', 'DisciplineShortName', 'DisciplineDescription']
        

class ProgramForm(forms.ModelForm):
    class Meta:
        model = Program
        fields = ['ProgramFullName', 'ProgramShortName', 'ProgramDuration', 'ProgramDescription']

class AYForm(forms.ModelForm):
    AY_STATUS_CHOICES = [
        ('Current', 'Current'),
        ('Completed', 'Completed'),
        ('Not Offered', 'Not Offered')
    ]
    
    AYStatus = forms.ChoiceField(choices=AY_STATUS_CHOICES, widget=forms.Select(attrs={'class': 'border border-gray-300 rounded-md py-2 px-3 w-full mx-5'}))
    AYStartDate = forms.DateField(widget=forms.DateInput(attrs={'type': 'date', 'class': 'border border-gray-300 rounded-md py-2 px-3 w-full mx-5'}))
    AYEndDate = forms.DateField(widget=forms.DateInput(attrs={'type': 'date', 'class': 'border border-gray-300 rounded-md py-2 px-3 w-full mx-5'}))

    class Meta:
        model = AcademicYear
        fields = ['AYStatus', 'AYStartDate', 'AYEndDate']
    
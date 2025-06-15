from django.contrib.auth.models import AbstractUser
from django.contrib.sessions.models import Session
from django.db import models
from argon2 import PasswordHasher, exceptions
from django.utils import timezone
from datetime import timedelta
import pyotp
import random, string

class Program(models.Model):
    ProgramID = models.CharField(max_length=10, primary_key=True)
    ProgramFullName = models.CharField(max_length=50)
    ProgramShortName = models.CharField(max_length=15)
    ProgramDuration = models.PositiveSmallIntegerField()
    ProgramDescription = models.TextField()

    def __str__(self):
        return self.ProgramID

    class Meta:
        managed = True
        db_table = 'program'


class Discipline(models.Model):
    DisciplineID = models.CharField('Discipline', db_column='DisciplineID', max_length=10, primary_key=True)
    DisciplineFullName = models.CharField(max_length=50)
    DisciplineShortName = models.CharField(max_length=10, blank=True, null=True)
    DisciplineDescription = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.DisciplineID

    class Meta:
        managed = True
        db_table = 'discipline'

class Batch(models.Model):
    BatchID = models.CharField(max_length=10, primary_key=True)
    BatchYear = models.SmallIntegerField()
    TotalStudent = models.SmallIntegerField()
    BatchDescription = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.BatchID

    class Meta:
        managed = True
        db_table = 'batch'



class Course(models.Model):

    CourseNumber = models.CharField(max_length=10, primary_key=True)

    ProgramID = models.ForeignKey('Program', db_column='ProgramID', on_delete=models.CASCADE)

    CourseName = models.CharField(max_length=100)

    CourseCredits = models.PositiveSmallIntegerField()

    Deleted = models.BooleanField(default=False)

    CourseDescription = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'course'
        
    def __str__(self):
        return self.CourseNumber

class BaseChart(models.Model):
    BaseChartID = models.CharField(max_length=10, primary_key=True)
    CreatedDate = models.DateTimeField()
    ModifiedDate = models.DateTimeField()
    ProgramID = models.ForeignKey('Program', db_column='ProgramID', on_delete=models.CASCADE)
    BatchID = models.ForeignKey('Batch', db_column='BatchID', on_delete=models.CASCADE)
    DisciplineID = models.ForeignKey('Discipline', db_column='DisciplineID', on_delete=models.CASCADE)


    class Meta:
        db_table = 'basechart'

class OfferedCourses(models.Model):
    BaseChartID = models.ForeignKey('BaseChart', db_column='BaseChartID', on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber', on_delete=models.CASCADE)
    CourseCredits = models.PositiveSmallIntegerField()
    YearNumber = models.PositiveSmallIntegerField()
    SemesterPeriodNumber = models.CharField(max_length=10)
    Deleted = models.BooleanField(default=False)

    class Meta:
        db_table = 'offeredcourses'
        unique_together = [['BaseChartID', 'CourseNumber', 'SemesterPeriodNumber']]  # Assuming this combination should be unique

    def __str__(self):
        return f"{self.BaseChartID} - {self.CourseNumber} - {self.SemesterNumber}"
    

class AcademicYear(models.Model):
    AY_ID = models.CharField(max_length=10, primary_key=True)
    AYStatus = models.CharField(max_length=50)
    AYStartDate = models.DateField()
    AYEndDate = models.DateField()
    AYCreateDate = models.DateField()

    class Meta:
        db_table = 'academicyear'

    def __str__(self):
        return self.AY_ID


class DisciplineCourse(models.Model):
    DisciplineID = models.ForeignKey('Discipline', db_column='DisciplineID',on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber',on_delete=models.CASCADE)
    CourseType = models.CharField(db_column='CourseType',max_length=20, null=False, blank=False)

    class Meta:
        db_table = 'disciplinecourse'
        unique_together = [['DisciplineID', 'CourseNumber']]

    def __str__(self):
        return f"{self.DisciplineID} - {self.CourseNumber}"
    

class GradePoint(models.Model):
    GradePointID = models.CharField(max_length=10, primary_key=True)
    Grade = models.CharField(max_length=2)
    GradePointValue = models.DecimalField(max_digits=4, decimal_places=2)

    class Meta:
        db_table = 'gradepoint'

    def __str__(self):
        return f"{self.GradePointID} - {self.Grade} - {self.GradePointValue}"
        
class MIITRole(models.Model):
    RoleID = models.CharField(max_length=10, primary_key=True)
    RoleDescription = models.TextField()

    class Meta:
        db_table = 'miitrole'

    def __str__(self):
        return self.RoleID
    

class MIITUsers(AbstractUser):
    password = None
    last_login = None
    is_superuser = None
    first_name = None
    last_name = None
    is_staff = None
    is_active = None
    date_joined = None
    email = None


    UserID = models.CharField(db_column='UserID', max_length=10, primary_key=True)
    username = models.EmailField(db_column='Email', max_length=50, unique=True)
    UserPasswordKey = models.CharField(db_column='UserPasswordKey', max_length=255)
    UserStatus = models.CharField(db_column='UserStatus', max_length=25)
    Deleted = models.BooleanField(default=False)

    mfa_enabled = models.BooleanField(default=False)
    acc_locked = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)
    backup_codes = models.TextField(blank=True, null=True)


    class Meta:
        db_table = 'miitusers'

    def set_password(self, raw_password):
        # Initialize a PasswordHasher object with increased time and memory costs
        ph = PasswordHasher(time_cost=4, memory_cost=65536)

        # Generate the Argon2 hash with the provided password
        hashed_password = ph.hash(raw_password)

        # Set the hashed password in the model instance
        self.UserPasswordKey = hashed_password

    def check_password(self, raw_password):
        ph = PasswordHasher(time_cost=4, memory_cost=65536)
        try:
            return ph.verify(self.UserPasswordKey, raw_password)
        except exceptions.VerifyMismatchError:
            return False
        
    def generate_mfa_secret(self):
        self.mfa_secret = pyotp.random_base32()
        self.save()

    def generate_backup_codes(self):
        codes = [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(10)]
        self.backup_codes = ','.join(codes)
        self.save()
        return codes
    
    def __str__(self):
        return self.UserID
    
# class MIITUsers(models.Model):
#     UserID = models.CharField(max_length=10, primary_key=True)
#     Email = models.CharField(max_length=50, unique=True)
#     UserPasswordKey = models.CharField(max_length=255)
#     UserStatus = models.CharField(max_length=25)
#     CreatedDate = models.DateTimeField(auto_now_add=True)
#     ModifiedDate = models.DateTimeField(auto_now=True)
#     LastLoginDate = models.DateTimeField(blank=True, null=True)

#     class Meta:
#         db_table = 'miitusers'

#     def __str__(self):
#         return self.UserID


class Student(models.Model):
    StudentID = models.CharField(max_length=10, primary_key=True)
    MIITID = models.CharField(max_length=10, blank=True, null=True)
    UserID = models.ForeignKey('MIITUsers', db_column='UserID', on_delete=models.CASCADE)
    DisciplineID = models.ForeignKey('Discipline', db_column='DisciplineID', on_delete=models.CASCADE)
    ProgramID = models.ForeignKey('Program', db_column='ProgramID', on_delete=models.CASCADE)
    BatchID = models.ForeignKey('Batch', db_column='BatchID', on_delete=models.CASCADE)
    StudentName = models.CharField(max_length=50)
    Salutation = models.CharField(max_length=20)
    SectionName = models.CharField(max_length=10)
    RollNumber = models.CharField(max_length=50)
    StudentNRC = models.CharField(max_length=50, blank=True, null=True)
    StudentPhone = models.CharField(max_length=20, blank=True, null=True)
    StudentDOB = models.DateField(blank=True, null=True)
    ACBStatus = models.PositiveSmallIntegerField()
    Nationality = models.CharField(max_length=100, blank=True, null=True)
    Religion = models.CharField(max_length=50, blank=True, null=True)
    MatricRollNumber = models.CharField(max_length=50, blank=True, null=True)
    MatricExamYear = models.CharField(max_length=4, blank=True, null=True)
    FatherName = models.CharField(max_length=50, blank=True, null=True)
    FatherNRC = models.CharField(max_length=50, blank=True, null=True)
    FatherPhoneNumber = models.CharField(max_length=20, blank=True, null=True)
    MotherName = models.CharField(max_length=50, blank=True, null=True)
    MotherNRC = models.CharField(max_length=50, blank=True, null=True)
    MotherPhoneNumber = models.CharField(max_length=20, blank=True, null=True)
    Address = models.TextField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'student'

    def __str__(self):
        return f"{self.StudentName}"
    

class FacultyStaff(models.Model):
    FacultyStaffID = models.CharField(max_length=10, primary_key=True)
    UserID = models.ForeignKey('MIITUsers', db_column = 'UserID', on_delete=models.CASCADE)
    Salutation = models.CharField(max_length=50)
    FacultyStaffName = models.CharField(max_length=50)
    ShortName = models.CharField(max_length=10)
    Designation = models.CharField(max_length=50)
    Department = models.CharField(max_length=50)
    NRC = models.CharField(max_length=50, blank=True, null=True)
    Phone = models.CharField(max_length=20, blank=True, null=True)
    Address = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'facultystaff'

    def __str__(self):
	    return f"{self.FacultyStaffName}"


class Semester(models.Model):
    SemesterID = models.CharField(max_length=10, primary_key=True)
    AY_ID = models.ForeignKey('AcademicYear', db_column='AY_ID', on_delete=models.CASCADE)
    ProgramID = models.ForeignKey('Program', db_column='ProgramID', on_delete=models.CASCADE)
    SemesterStatus = models.CharField(max_length=20)
    SemesterStartDate = models.DateField()
    SemesterEndDate = models.DateField()
    SemesterDescription = models.TextField(blank=True)

    class Meta:
        db_table = 'semester'

    def __str__(self):
        return self.SemesterID

class MIITUserRole(models.Model):
    UserID = models.ForeignKey('MIITUsers', db_column='UserID', on_delete=models.CASCADE)
    RoleID = models.ForeignKey('MIITRole', db_column='RoleID', on_delete=models.CASCADE)

    class Meta:
        db_table = 'miituserrole'
        unique_together = [['UserID', 'RoleID']]

    def __str__(self):
        return f"{self.UserID} - {self.RoleID}"
  

class SemesterGrading(models.Model):
    SemesterGradingID = models.CharField(max_length=10, primary_key=True)
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE) 
    SemesterID = models.ForeignKey('Semester', db_column='SemesterID', on_delete=models.CASCADE)
    SemesterPeriodNumber = models.CharField(max_length=10)
    Deleted = models.BooleanField(default=False)

    class Meta:
        db_table = 'semestergrading'

    def __str__(self):
        return f"{self.SemesterGradingID} - {self.StudentID} - {self.SemesterID}"


class CourseGrading(models.Model):
    SemesterGradingID = models.ForeignKey('SemesterGrading', db_column='SemesterGradingID', on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber', on_delete=models.CASCADE)
    GradePointID = models.ForeignKey('GradePoint', db_column='GradePointID', on_delete=models.CASCADE)

    class Meta:
        db_table = 'coursegrading'
        unique_together = ('SemesterGradingID', 'CourseNumber')
        

    def __str__(self):
        return f"{self.SemesterGradingID} - {self.CourseNumber} - {self.GradePointID}"


class Project(models.Model):
    ProjectNumber = models.CharField(max_length=10, primary_key=True)
    FacultyStaffID = models.ForeignKey('FacultyStaff', db_column='FacultyStaffID', on_delete=models.CASCADE)
    SemesterID = models.ForeignKey('Semester', db_column='SemesterID', on_delete=models.CASCADE)
    ProgramID = models.ForeignKey('Program', db_column='ProgramID', on_delete=models.CASCADE)
    ProjectTitle = models.CharField(max_length=100)
    ProjectCredits = models.IntegerField()
    NumberStudents = models.IntegerField('Project', db_column='NumbStudents') 
    ProjectSummary = models.TextField(blank=True)
    Deleted = models.BooleanField(default=False)
    ProjectType = models.IntegerField()
    Remarks = models.TextField(blank=True)

    class Meta:
        db_table = 'project'

    def __str__(self):
        return self.ProjectNumber
    

class News(models.Model):
    title = models.CharField(max_length=500)
    description = models.TextField(null=True, blank=True)
    url = models.URLField()
    source = models.CharField(max_length=100)
    published_at = models.DateTimeField()
    url_to_image = models.URLField(max_length=500, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


    class Meta:
        db_table = 'academia_news'


    def __str__(self):
        return self.title
    


###########################---------------------------------------------------------------------------

class FacultyCourse(models.Model):
    FacultyStaffID = models.ForeignKey('FacultyStaff', db_column='FacultyStaffID', on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber', on_delete=models.CASCADE)
    BatchID = models.ForeignKey('Batch', db_column='BatchID', on_delete=models.CASCADE)
    SemesterID = models.ForeignKey('Semester', db_column='SemesterID', on_delete=models.CASCADE)
    Section = models.CharField(max_length=255)
    Deleted = models.BooleanField(default=False)

    class Meta:
        db_table = 'facultycourse'
        unique_together = [['FacultyStaffID', 'CourseNumber', 'BatchID', 'SemesterID', 'Section']]
        managed = False

    def __str__(self):
        return f"{self.FacultyStaffID} - {self.CourseNumber} - {self.BatchID} - {self.SemesterID} - {self.Section}"


class FacultyUploadGrade(models.Model):
    FacultyStaffID = models.ForeignKey('FacultyStaff', db_column='FacultyStaffID', on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber', on_delete=models.CASCADE)
    SemesterID = models.ForeignKey('Semester', db_column='SemesterID', on_delete=models.CASCADE)
    RollNumber = models.CharField(max_length=50)
    Grade = models.CharField(max_length=5)

    class Meta:
        db_table = 'facultyuploadgrade'
        unique_together = [['FacultyStaffID', 'CourseNumber', 'SemesterID', 'RollNumber']]
        managed = False

    def __str__(self):
        return f"{self.FacultyStaffID} - {self.CourseNumber} - {self.SemesterID} - {self.RollNumber}"



class StudentSemesterRegistration(models.Model):
    RegistrationID = models.CharField(max_length=10, primary_key=True)
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE)
    SemesterID = models.ForeignKey('Semester', db_column='SemesterID', on_delete=models.CASCADE)
    SemesterPeriodName = models.CharField(max_length=20)
    SemesterPeriodNumber = models.PositiveSmallIntegerField()
    YearNumber = models.PositiveSmallIntegerField()
    RegistrationDate = models.DateField()
    RegistrationTime = models.TimeField()
    Remarks = models.TextField(blank=True, null=True)
    Deleted = models.BooleanField(default=False)

    class Meta:
        db_table = 'studentsemesterregistration'
        managed = False

    def __str__(self):
        return f"{self.RegistrationID} - {self.StudentID} - {self.SemesterID}"



class StudentProjectRegistration(models.Model):
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE)
    ProjectNumber = models.ForeignKey('Project', db_column='ProjectNumber', on_delete=models.CASCADE)
    RegistrationID = models.ForeignKey('StudentSemesterRegistration', db_column='RegistrationID', on_delete=models.CASCADE)
    ProjectCode = models.CharField(max_length=10)
    ProjectAlloted = models.BooleanField(default=False)
    CompleteStatus = models.CharField(max_length=20)

    class Meta:
        db_table = 'studentprojectregistration'
        unique_together = [['StudentID', 'ProjectNumber', 'RegistrationID']]
        managed = False

    def __str__(self):
        return f"{self.StudentID} - {self.ProjectNumber} - {self.RegistrationID}"



class SemesterBacklogs(models.Model):
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE)
    RegistrationID = models.ForeignKey('StudentSemesterRegistration', db_column='RegistrationID', on_delete=models.CASCADE)
    BacklogStatus = models.CharField(max_length=20)

    class Meta:
        db_table = 'semesterbacklogs'
        unique_together = [['StudentID', 'RegistrationID']]
        managed = False

    def __str__(self):
        return f"{self.StudentID} - {self.RegistrationID} - {self.BacklogStatus}"



class BacklogStudentProject(models.Model):
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE)
    ProjectNumber = models.ForeignKey('Project', db_column='ProjectNumber', on_delete=models.CASCADE)
    BacklogProjectStatus = models.CharField(max_length=20)
    BacklogProjectDescription = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'backlogstudentproject'
        unique_together = [['StudentID', 'ProjectNumber']]
        managed = False

    def __str__(self):
        return f"{self.StudentID} - {self.ProjectNumber}"



class BacklogStudentCourse(models.Model):
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber', on_delete=models.CASCADE)
    BacklogStatus = models.CharField(max_length=20)
    BacklogType = models.CharField(max_length=30)
    BacklogDescription = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'backlogstudentcourse'
        unique_together = [['StudentID', 'CourseNumber']]
        managed = False

    def __str__(self):
        return f"{self.StudentID} - {self.CourseNumber}"



class CarryCourses(models.Model):
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE)
    SemesterID = models.ForeignKey('Semester', db_column='SemesterID', on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber', on_delete=models.CASCADE)
    CarryCourseStatus = models.CharField(max_length=20)

    class Meta:
        db_table = 'carrycourses'
        unique_together = [['StudentID', 'SemesterID', 'CourseNumber']]
        managed = False

    def __str__(self):
        return f"{self.StudentID} - {self.SemesterID} - {self.CourseNumber}"




class RegisteredCourses(models.Model):
    RegistrationID = models.ForeignKey('StudentSemesterRegistration', db_column='RegistrationID', on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber', on_delete=models.CASCADE)
    Deleted = models.BooleanField(default=False)

    class Meta:
        db_table = 'registeredcourses'
        unique_together = [['RegistrationID', 'CourseNumber']]
        managed = False

    def __str__(self):
        return f"{self.RegistrationID} - {self.CourseNumber}"


class GradeSheetData(models.Model):
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE)
    SemesterID = models.ForeignKey('Semester', db_column='SemesterID', on_delete=models.CASCADE)
    SemesterCredits = models.PositiveSmallIntegerField()
    AccumulatedCredits = models.PositiveSmallIntegerField()
    SGPA = models.DecimalField(max_digits=4, decimal_places=2)
    CGPA = models.DecimalField(max_digits=4, decimal_places=2)

    class Meta:
        db_table = 'gradesheetdata'
        unique_together = [['StudentID', 'SemesterID']]
        managed = False
        ordering = ['StudentID', 'SemesterID']  # Specify the ordering to avoid default 'id' usage

    def __str__(self):
        return f"{self.StudentID} - {self.SemesterID} - {self.SGPA} - {self.CGPA}"



class Attendance(models.Model):
    id = models.AutoField(primary_key=True)
    FacultyStaffID = models.ForeignKey('FacultyStaff', db_column='FacultyStaffID', on_delete=models.CASCADE)
    SemesterID = models.ForeignKey('Semester', db_column='SemesterID', on_delete=models.CASCADE)
    CourseNumber = models.ForeignKey('Course', db_column='CourseNumber', on_delete=models.CASCADE)
    StartDate = models.DateField()
    EndDate = models.DateField()

    class Meta:
        db_table = 'attendance'

    def __str__(self):
        return f"Attendance for {self.CourseNumber} by {self.FacultyStaffID}"


class StudentAttendance(models.Model):
    AttendanceID = models.ForeignKey('Attendance', db_column='AttendanceID', on_delete=models.CASCADE)
    StudentID = models.ForeignKey('Student', db_column='StudentID', on_delete=models.CASCADE)
    BatchID = models.ForeignKey('Batch', db_column='BatchID', on_delete=models.CASCADE)
    TotalSections = models.IntegerField()
    PresentSections = models.IntegerField()
    Percentage = models.DecimalField(max_digits=5, decimal_places=2)

    class Meta:
        db_table = 'studentattendance'

    def __str__(self):
        return f"Attendance record for {self.StudentID} in {self.AttendanceID.CourseNumber}"
    


class PasswordResetToken(models.Model):
    email = models.EmailField(max_length=255)
    token_hash = models.CharField(max_length=255)
    expires_at = models.DateTimeField()

    class Meta:
        db_table = 'passwordresettoken'

    def save(self, *args, **kwargs):
        if not self.id:
            self.expires_at = timezone.now() + timedelta(minutes=15)
        super().save(*args, **kwargs)



class UserDevice(models.Model):
    user = models.ForeignKey('MIITUsers', on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True)
    device_name = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=45)
    browser = models.CharField(max_length=255)
    os = models.CharField(max_length=255)
    device_type = models.CharField(max_length=255)
    last_activity = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'userdevice'


class LoginHistory(models.Model):
    user = models.ForeignKey(MIITUsers, on_delete=models.CASCADE)
    login_time = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'loginhistory'

    def __str__(self):
        return f"{self.user.username} logged in at {self.login_time}"


class NotificationPreference(models.Model):
    user = models.OneToOneField(MIITUsers, on_delete=models.CASCADE)
    grades_alert = models.BooleanField(default=True)
    attendance_alert = models.BooleanField(default=True)
    exam_schedule_alert = models.BooleanField(default=True)
    institutional_announcement_alert = models.BooleanField(default=True)
    event_notification_alert = models.BooleanField(default=True)
    news_alert = models.BooleanField(default=True)

    class Meta:
        db_table = 'notificationpreference'

    def __str__(self):
        return f"Notification preferences for {self.user.username}"


class Event(models.Model):
    event_id = models.AutoField(db_column='event_id', primary_key=True)
    title = models.CharField(max_length=255, null=False)
    event_description = models.TextField(blank=True, null=True)
    start_time = models.DateTimeField(null=False)
    end_time = models.DateTimeField(null=False)
    location = models.CharField(max_length=255, blank=True, null=True)
    event_type = models.CharField(max_length=50, null=False)
    organizer_details = models.CharField(max_length=255, blank=True, null=True)
    target_audience = models.CharField(max_length=255, blank=True, null=True)
    rsvp_registration = models.BooleanField(default=False)
    capacity = models.IntegerField(blank=True, null=True)
    attachment_path = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def str(self):
        return self.title

    class Meta:
        db_table = 'events'
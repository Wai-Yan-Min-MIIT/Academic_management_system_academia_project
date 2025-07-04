# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class AcademiaNews(models.Model):
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True, null=True)
    url = models.CharField(max_length=200)
    source = models.CharField(max_length=100)
    published_at = models.DateTimeField()
    url_to_image = models.CharField(max_length=500, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'academia_news'


class Academicyear(models.Model):
    ay_id = models.CharField(db_column='AY_ID', primary_key=True, max_length=10)  # Field name made lowercase.
    aystartdate = models.DateField(db_column='AYStartDate')  # Field name made lowercase.
    ayenddate = models.DateField(db_column='AYEndDate')  # Field name made lowercase.
    aycreatedate = models.DateField(db_column='AYCreateDate')  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'academicyear'


class AuthGroup(models.Model):
    name = models.CharField(unique=True, max_length=150)

    class Meta:
        managed = False
        db_table = 'auth_group'


class AuthGroupPermissions(models.Model):
    id = models.BigAutoField(primary_key=True)
    group = models.ForeignKey(AuthGroup, models.DO_NOTHING)
    permission = models.ForeignKey('AuthPermission', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'auth_group_permissions'
        unique_together = (('group', 'permission'),)


class AuthPermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING)
    codename = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'auth_permission'
        unique_together = (('content_type', 'codename'),)


class Backlogstudentcourse(models.Model):
    studentid = models.ForeignKey('Student', models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    coursecode = models.ForeignKey('Course', models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.
    backlogstatus = models.CharField(db_column='BacklogStatus', max_length=20)  # Field name made lowercase.
    backlogtype = models.CharField(db_column='BacklogType', max_length=30)  # Field name made lowercase.
    backlogdescription = models.TextField(db_column='BacklogDescription', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'backlogstudentcourse'


class Backlogstudentproject(models.Model):
    studentid = models.ForeignKey('Student', models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    projectnumber = models.ForeignKey('Project', models.DO_NOTHING, db_column='ProjectNumber', blank=True, null=True)  # Field name made lowercase.
    backlogprojectstatus = models.CharField(db_column='BacklogProjectStatus', max_length=20)  # Field name made lowercase.
    backlogprojectdescription = models.TextField(db_column='BacklogProjectDescription', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'backlogstudentproject'


class Basechart(models.Model):
    basechartid = models.CharField(db_column='BaseChartID', primary_key=True, max_length=10)  # Field name made lowercase.
    pbd = models.ForeignKey('Programbatchdiscipline', models.DO_NOTHING, db_column='PBD_ID', blank=True, null=True)  # Field name made lowercase.
    createddate = models.DateTimeField(db_column='CreatedDate', blank=True, null=True)  # Field name made lowercase.
    modifieddate = models.DateTimeField(db_column='ModifiedDate', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'basechart'


class Batch(models.Model):
    batchid = models.CharField(db_column='BatchID', primary_key=True, max_length=10)  # Field name made lowercase.
    batchyear = models.SmallIntegerField(db_column='BatchYear')  # Field name made lowercase.
    totalstudent = models.SmallIntegerField(db_column='TotalStudent')  # Field name made lowercase.
    batchdescription = models.TextField(db_column='BatchDescription', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'batch'


class Carrycourses(models.Model):
    studentid = models.ForeignKey('Student', models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    semesterid = models.ForeignKey('Semester', models.DO_NOTHING, db_column='SemesterID', blank=True, null=True)  # Field name made lowercase.
    coursecode = models.ForeignKey('Course', models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.
    carrycoursestatus = models.CharField(db_column='CarryCourseStatus', max_length=20, blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'carrycourses'


class Course(models.Model):
    coursecode = models.CharField(db_column='CourseCode', primary_key=True, max_length=10)  # Field name made lowercase.
    programid = models.ForeignKey('Program', models.DO_NOTHING, db_column='ProgramID', blank=True, null=True)  # Field name made lowercase.
    coursename = models.CharField(db_column='CourseName', max_length=100)  # Field name made lowercase.
    coursecredits = models.IntegerField(db_column='CourseCredits')  # Field name made lowercase.
    deleted = models.IntegerField(db_column='Deleted', blank=True, null=True)  # Field name made lowercase.
    coursedescription = models.TextField(db_column='CourseDescription', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'course'


class Coursegrading(models.Model):
    semestergradingid = models.ForeignKey('Semestergrading', models.DO_NOTHING, db_column='SemesterGradingID', blank=True, null=True)  # Field name made lowercase.
    coursecode = models.ForeignKey(Course, models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.
    gradepointid = models.ForeignKey('Gradepoint', models.DO_NOTHING, db_column='GradePointID', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'coursegrading'


class Discipline(models.Model):
    disciplineid = models.CharField(db_column='DisciplineID', primary_key=True, max_length=10)  # Field name made lowercase.
    disciplinefullname = models.CharField(db_column='DisciplineFullName', max_length=50)  # Field name made lowercase.
    disciplineshortname = models.CharField(db_column='DisciplineShortName', max_length=10, blank=True, null=True)  # Field name made lowercase.
    disciplinedescription = models.TextField(db_column='DisciplineDescription', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'discipline'


class Disciplinecourse(models.Model):
    disciplineid = models.ForeignKey(Discipline, models.DO_NOTHING, db_column='DisciplineID', blank=True, null=True)  # Field name made lowercase.
    coursecode = models.ForeignKey(Course, models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'disciplinecourse'


class DjangoAdminLog(models.Model):
    action_time = models.DateTimeField()
    object_id = models.TextField(blank=True, null=True)
    object_repr = models.CharField(max_length=200)
    action_flag = models.PositiveSmallIntegerField()
    change_message = models.TextField()
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING, blank=True, null=True)
    user = models.ForeignKey('Miitusers', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'django_admin_log'


class DjangoApschedulerDjangojob(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    next_run_time = models.DateTimeField(blank=True, null=True)
    job_state = models.TextField()

    class Meta:
        managed = False
        db_table = 'django_apscheduler_djangojob'


class DjangoApschedulerDjangojobexecution(models.Model):
    id = models.BigAutoField(primary_key=True)
    status = models.CharField(max_length=50)
    run_time = models.DateTimeField()
    duration = models.DecimalField(max_digits=15, decimal_places=2, blank=True, null=True)
    finished = models.DecimalField(max_digits=15, decimal_places=2, blank=True, null=True)
    exception = models.CharField(max_length=1000, blank=True, null=True)
    traceback = models.TextField(blank=True, null=True)
    job = models.ForeignKey(DjangoApschedulerDjangojob, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'django_apscheduler_djangojobexecution'
        unique_together = (('job', 'run_time'),)


class DjangoCeleryBeatClockedschedule(models.Model):
    clocked_time = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_celery_beat_clockedschedule'


class DjangoCeleryBeatCrontabschedule(models.Model):
    minute = models.CharField(max_length=240)
    hour = models.CharField(max_length=96)
    day_of_week = models.CharField(max_length=64)
    day_of_month = models.CharField(max_length=124)
    month_of_year = models.CharField(max_length=64)
    timezone = models.CharField(max_length=63)

    class Meta:
        managed = False
        db_table = 'django_celery_beat_crontabschedule'


class DjangoCeleryBeatIntervalschedule(models.Model):
    every = models.IntegerField()
    period = models.CharField(max_length=24)

    class Meta:
        managed = False
        db_table = 'django_celery_beat_intervalschedule'


class DjangoCeleryBeatPeriodictask(models.Model):
    name = models.CharField(unique=True, max_length=200)
    task = models.CharField(max_length=200)
    args = models.TextField()
    kwargs = models.TextField()
    queue = models.CharField(max_length=200, blank=True, null=True)
    exchange = models.CharField(max_length=200, blank=True, null=True)
    routing_key = models.CharField(max_length=200, blank=True, null=True)
    expires = models.DateTimeField(blank=True, null=True)
    enabled = models.IntegerField()
    last_run_at = models.DateTimeField(blank=True, null=True)
    total_run_count = models.PositiveIntegerField()
    date_changed = models.DateTimeField()
    description = models.TextField()
    crontab = models.ForeignKey(DjangoCeleryBeatCrontabschedule, models.DO_NOTHING, blank=True, null=True)
    interval = models.ForeignKey(DjangoCeleryBeatIntervalschedule, models.DO_NOTHING, blank=True, null=True)
    solar = models.ForeignKey('DjangoCeleryBeatSolarschedule', models.DO_NOTHING, blank=True, null=True)
    one_off = models.IntegerField()
    start_time = models.DateTimeField(blank=True, null=True)
    priority = models.PositiveIntegerField(blank=True, null=True)
    headers = models.TextField()
    clocked = models.ForeignKey(DjangoCeleryBeatClockedschedule, models.DO_NOTHING, blank=True, null=True)
    expire_seconds = models.PositiveIntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'django_celery_beat_periodictask'


class DjangoCeleryBeatPeriodictasks(models.Model):
    ident = models.SmallIntegerField(primary_key=True)
    last_update = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_celery_beat_periodictasks'


class DjangoCeleryBeatSolarschedule(models.Model):
    event = models.CharField(max_length=24)
    latitude = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)

    class Meta:
        managed = False
        db_table = 'django_celery_beat_solarschedule'
        unique_together = (('event', 'latitude', 'longitude'),)


class DjangoContentType(models.Model):
    app_label = models.CharField(max_length=100)
    model = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'django_content_type'
        unique_together = (('app_label', 'model'),)


class DjangoMigrations(models.Model):
    id = models.BigAutoField(primary_key=True)
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_migrations'


class DjangoSession(models.Model):
    session_key = models.CharField(primary_key=True, max_length=40)
    session_data = models.TextField()
    expire_date = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_session'


class Elective(models.Model):
    electivecoursecode = models.CharField(db_column='ElectiveCourseCode', primary_key=True, max_length=10)  # Field name made lowercase.
    coursecode = models.ForeignKey(Course, models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.
    deleted = models.IntegerField(db_column='Deleted', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'elective'


class Facultycourse(models.Model):
    facultystaffid = models.ForeignKey('Facultystaff', models.DO_NOTHING, db_column='FacultyStaffID', blank=True, null=True)  # Field name made lowercase.
    coursecode = models.ForeignKey(Course, models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.
    batchid = models.ForeignKey(Batch, models.DO_NOTHING, db_column='BatchID', blank=True, null=True)  # Field name made lowercase.
    disciplineid = models.ForeignKey(Discipline, models.DO_NOTHING, db_column='DisciplineID', blank=True, null=True)  # Field name made lowercase.
    deleted = models.IntegerField(db_column='Deleted', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'facultycourse'


class Facultystaff(models.Model):
    facultystaffid = models.CharField(db_column='FacultyStaffID', primary_key=True, max_length=10)  # Field name made lowercase.
    userid = models.ForeignKey('Miitusers', models.DO_NOTHING, db_column='UserID', blank=True, null=True)  # Field name made lowercase.
    salutation = models.CharField(db_column='Salutation', max_length=50, blank=True, null=True)  # Field name made lowercase.
    facultystaffname = models.CharField(db_column='FacultyStaffName', max_length=50)  # Field name made lowercase.
    shortname = models.CharField(db_column='ShortName', max_length=10)  # Field name made lowercase.
    designation = models.CharField(db_column='Designation', max_length=50)  # Field name made lowercase.
    department = models.CharField(db_column='Department', max_length=50)  # Field name made lowercase.
    nrc = models.CharField(db_column='NRC', max_length=50, blank=True, null=True)  # Field name made lowercase.
    phone = models.CharField(db_column='Phone', max_length=20, blank=True, null=True)  # Field name made lowercase.
    address = models.TextField(db_column='Address', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'facultystaff'


class Facultyuploadgrade(models.Model):
    facultystaffid = models.ForeignKey(Facultystaff, models.DO_NOTHING, db_column='FacultyStaffID', blank=True, null=True)  # Field name made lowercase.
    coursecode = models.ForeignKey(Course, models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.
    semesterid = models.ForeignKey('Semester', models.DO_NOTHING, db_column='SemesterID', blank=True, null=True)  # Field name made lowercase.
    rollnumber = models.CharField(db_column='RollNumber', max_length=50)  # Field name made lowercase.
    grade = models.CharField(db_column='Grade', max_length=5)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'facultyuploadgrade'


class Gradepoint(models.Model):
    gradepointid = models.CharField(db_column='GradePointID', primary_key=True, max_length=10)  # Field name made lowercase.
    grade = models.CharField(db_column='Grade', max_length=5)  # Field name made lowercase.
    gradepointvalue = models.FloatField(db_column='GradePointValue')  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'gradepoint'


class Gradesheetdata(models.Model):
    studentid = models.ForeignKey('Student', models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    semesterid = models.ForeignKey('Semester', models.DO_NOTHING, db_column='SemesterID', blank=True, null=True)  # Field name made lowercase.
    semestercredits = models.IntegerField(db_column='SemesterCredits')  # Field name made lowercase.
    accumulatedcredits = models.SmallIntegerField(db_column='AccumulatedCredits')  # Field name made lowercase.
    sgpa = models.FloatField(db_column='SGPA')  # Field name made lowercase.
    cgpa = models.FloatField(db_column='CGPA')  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'gradesheetdata'


class Miitrole(models.Model):
    roleid = models.CharField(db_column='RoleID', primary_key=True, max_length=10)  # Field name made lowercase.
    roledescription = models.TextField(db_column='RoleDescription', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'miitrole'


class Miituserrole(models.Model):
    userid = models.ForeignKey('Miitusers', models.DO_NOTHING, db_column='UserID', blank=True, null=True)  # Field name made lowercase.
    roleid = models.ForeignKey(Miitrole, models.DO_NOTHING, db_column='RoleID', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'miituserrole'


class Miitusers(models.Model):
    userid = models.CharField(db_column='UserID', primary_key=True, max_length=10)  # Field name made lowercase.
    email = models.CharField(db_column='Email', unique=True, max_length=50)  # Field name made lowercase.
    userpasswordkey = models.CharField(db_column='UserPasswordKey', max_length=255)  # Field name made lowercase.
    userstatus = models.CharField(db_column='UserStatus', max_length=25)  # Field name made lowercase.
    createddate = models.DateTimeField(db_column='CreatedDate', blank=True, null=True)  # Field name made lowercase.
    modifieddate = models.DateTimeField(db_column='ModifiedDate', blank=True, null=True)  # Field name made lowercase.
    lastlogindate = models.DateTimeField(db_column='LastLoginDate', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'miitusers'


class Offeredcourses(models.Model):
    basechartid = models.ForeignKey(Basechart, models.DO_NOTHING, db_column='BaseChartID', blank=True, null=True)  # Field name made lowercase.
    coursecode = models.ForeignKey(Course, models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.
    coursecredits = models.IntegerField(db_column='CourseCredits')  # Field name made lowercase.
    yearnumber = models.IntegerField(db_column='YearNumber', blank=True, null=True)  # Field name made lowercase.
    semesterperiodnumber = models.CharField(db_column='SemesterPeriodNumber', max_length=10, blank=True, null=True)  # Field name made lowercase.
    deleted = models.IntegerField(db_column='Deleted', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'offeredcourses'


class Program(models.Model):
    programid = models.CharField(db_column='ProgramID', primary_key=True, max_length=10)  # Field name made lowercase.
    programfullname = models.CharField(db_column='ProgramFullName', max_length=50)  # Field name made lowercase.
    programshortname = models.CharField(db_column='ProgramShortName', max_length=10)  # Field name made lowercase.
    programduration = models.IntegerField(db_column='ProgramDuration', blank=True, null=True)  # Field name made lowercase.
    programdescription = models.TextField(db_column='ProgramDescription', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'program'


class Programbatchdiscipline(models.Model):
    pbd_id = models.CharField(db_column='PBD_ID', primary_key=True, max_length=10)  # Field name made lowercase.
    programid = models.ForeignKey(Program, models.DO_NOTHING, db_column='ProgramID', blank=True, null=True)  # Field name made lowercase.
    batchid = models.ForeignKey(Batch, models.DO_NOTHING, db_column='BatchID', blank=True, null=True)  # Field name made lowercase.
    disciplineid = models.ForeignKey(Discipline, models.DO_NOTHING, db_column='DisciplineID', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'programbatchdiscipline'


class Project(models.Model):
    projectnumber = models.CharField(db_column='ProjectNumber', primary_key=True, max_length=10)  # Field name made lowercase.
    facultystaffid = models.ForeignKey(Facultystaff, models.DO_NOTHING, db_column='FacultyStaffID', blank=True, null=True)  # Field name made lowercase.
    semesterid = models.ForeignKey('Semester', models.DO_NOTHING, db_column='SemesterID', blank=True, null=True)  # Field name made lowercase.
    projecttitle = models.CharField(db_column='ProjectTitle', max_length=100)  # Field name made lowercase.
    projectcredits = models.IntegerField(db_column='ProjectCredits')  # Field name made lowercase.
    numbstudents = models.IntegerField(db_column='NumbStudents')  # Field name made lowercase.
    projectsummary = models.TextField(db_column='ProjectSummary', blank=True, null=True)  # Field name made lowercase.
    deleted = models.IntegerField(db_column='Deleted', blank=True, null=True)  # Field name made lowercase.
    projecttype = models.CharField(db_column='ProjectType', max_length=50)  # Field name made lowercase.
    remarks = models.TextField(db_column='Remarks', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'project'


class Projectgrading(models.Model):
    studentid = models.ForeignKey('Student', models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    projectnumber = models.ForeignKey(Course, models.DO_NOTHING, db_column='ProjectNumber', blank=True, null=True)  # Field name made lowercase.
    gradepointid = models.ForeignKey(Gradepoint, models.DO_NOTHING, db_column='GradePointID', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'projectgrading'


class Registeredcourses(models.Model):
    registrationid = models.ForeignKey('Studentsemesterregistration', models.DO_NOTHING, db_column='RegistrationID', blank=True, null=True)  # Field name made lowercase.
    coursecode = models.ForeignKey(Course, models.DO_NOTHING, db_column='CourseCode', blank=True, null=True)  # Field name made lowercase.
    deleted = models.IntegerField(db_column='Deleted', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'registeredcourses'


class Semester(models.Model):
    semesterid = models.CharField(db_column='SemesterID', primary_key=True, max_length=10)  # Field name made lowercase.
    ay = models.ForeignKey(Academicyear, models.DO_NOTHING, db_column='AY_ID', blank=True, null=True)  # Field name made lowercase.
    programid = models.ForeignKey(Program, models.DO_NOTHING, db_column='ProgramID', blank=True, null=True)  # Field name made lowercase.
    semesterstatus = models.CharField(db_column='SemesterStatus', max_length=20)  # Field name made lowercase.
    semesterstartdate = models.DateField(db_column='SemesterStartDate')  # Field name made lowercase.
    semesterenddate = models.DateField(db_column='SemesterEndDate')  # Field name made lowercase.
    semesterdescription = models.TextField(db_column='SemesterDescription', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'semester'


class Semesterbacklogs(models.Model):
    studentid = models.ForeignKey('Student', models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    registrationid = models.ForeignKey('Studentsemesterregistration', models.DO_NOTHING, db_column='RegistrationID', blank=True, null=True)  # Field name made lowercase.
    backlogstatus = models.CharField(db_column='BacklogStatus', max_length=20, blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'semesterbacklogs'


class Semestergrading(models.Model):
    semestergradingid = models.CharField(db_column='SemesterGradingID', primary_key=True, max_length=10)  # Field name made lowercase.
    studentid = models.ForeignKey('Student', models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    semesterid = models.ForeignKey(Semester, models.DO_NOTHING, db_column='SemesterID', blank=True, null=True)  # Field name made lowercase.
    semesterperiodnumber = models.CharField(db_column='SemesterPeriodNumber', max_length=10)  # Field name made lowercase.
    deleted = models.IntegerField(db_column='Deleted', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'semestergrading'


class Student(models.Model):
    studentid = models.CharField(db_column='StudentID', primary_key=True, max_length=10)  # Field name made lowercase.
    miitid = models.CharField(db_column='MIITID', max_length=10, blank=True, null=True)  # Field name made lowercase.
    userid = models.ForeignKey(Miitusers, models.DO_NOTHING, db_column='UserID', blank=True, null=True)  # Field name made lowercase.
    disciplineid = models.ForeignKey(Discipline, models.DO_NOTHING, db_column='DisciplineID', blank=True, null=True)  # Field name made lowercase.
    programid = models.ForeignKey(Program, models.DO_NOTHING, db_column='ProgramID', blank=True, null=True)  # Field name made lowercase.
    batchid = models.ForeignKey(Batch, models.DO_NOTHING, db_column='BatchID', blank=True, null=True)  # Field name made lowercase.
    studentname = models.CharField(db_column='StudentName', max_length=50)  # Field name made lowercase.
    salutation = models.CharField(db_column='Salutation', max_length=20)  # Field name made lowercase.
    sectionname = models.CharField(db_column='SectionName', max_length=10)  # Field name made lowercase.
    rollnumber = models.CharField(db_column='RollNumber', max_length=50)  # Field name made lowercase.
    studentnrc = models.CharField(db_column='StudentNRC', max_length=50, blank=True, null=True)  # Field name made lowercase.
    studentphone = models.CharField(db_column='StudentPhone', max_length=20, blank=True, null=True)  # Field name made lowercase.
    studentdob = models.DateField(db_column='StudentDOB', blank=True, null=True)  # Field name made lowercase.
    acbstatus = models.IntegerField(db_column='ACBStatus')  # Field name made lowercase.
    nationality = models.CharField(db_column='Nationality', max_length=100, blank=True, null=True)  # Field name made lowercase.
    religion = models.CharField(db_column='Religion', max_length=50, blank=True, null=True)  # Field name made lowercase.
    matricrollnumber = models.CharField(db_column='MatricRollNumber', max_length=50, blank=True, null=True)  # Field name made lowercase.
    matricexamyear = models.CharField(db_column='MatricExamYear', max_length=4, blank=True, null=True)  # Field name made lowercase.
    fathername = models.CharField(db_column='FatherName', max_length=50, blank=True, null=True)  # Field name made lowercase.
    fathernrc = models.CharField(db_column='FatherNRC', max_length=50, blank=True, null=True)  # Field name made lowercase.
    fatherphonenumber = models.CharField(db_column='FatherPhoneNumber', max_length=20, blank=True, null=True)  # Field name made lowercase.
    mothername = models.CharField(db_column='MotherName', max_length=50, blank=True, null=True)  # Field name made lowercase.
    mothernrc = models.CharField(db_column='MotherNRC', max_length=50, blank=True, null=True)  # Field name made lowercase.
    motherphonenumber = models.CharField(db_column='MotherPhoneNumber', max_length=20, blank=True, null=True)  # Field name made lowercase.
    address = models.TextField(db_column='Address', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'student'


class Studentprojectregistration(models.Model):
    studentid = models.ForeignKey(Student, models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    projectnumber = models.ForeignKey(Project, models.DO_NOTHING, db_column='ProjectNumber', blank=True, null=True)  # Field name made lowercase.
    registrationid = models.ForeignKey('Studentsemesterregistration', models.DO_NOTHING, db_column='RegistrationID', blank=True, null=True)  # Field name made lowercase.
    projectcode = models.CharField(db_column='ProjectCode', max_length=10)  # Field name made lowercase.
    projectalloted = models.IntegerField(db_column='ProjectAlloted', blank=True, null=True)  # Field name made lowercase.
    completestatus = models.CharField(db_column='CompleteStatus', max_length=20)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'studentprojectregistration'


class Studentsemesterregistration(models.Model):
    registrationid = models.CharField(db_column='RegistrationID', primary_key=True, max_length=10)  # Field name made lowercase.
    studentid = models.ForeignKey(Student, models.DO_NOTHING, db_column='StudentID', blank=True, null=True)  # Field name made lowercase.
    semesterid = models.ForeignKey(Semester, models.DO_NOTHING, db_column='SemesterID', blank=True, null=True)  # Field name made lowercase.
    semesterperiodname = models.CharField(db_column='SemesterPeriodName', max_length=20)  # Field name made lowercase.
    semesterperiodnumber = models.IntegerField(db_column='SemesterPeriodNumber')  # Field name made lowercase.
    yearnumber = models.IntegerField(db_column='YearNumber')  # Field name made lowercase.
    registrationdate = models.DateField(db_column='RegistrationDate', blank=True, null=True)  # Field name made lowercase.
    registrationtime = models.TimeField(db_column='RegistrationTime', blank=True, null=True)  # Field name made lowercase.
    remarks = models.TextField(db_column='Remarks', blank=True, null=True)  # Field name made lowercase.
    deleted = models.IntegerField(db_column='Deleted', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'studentsemesterregistration'

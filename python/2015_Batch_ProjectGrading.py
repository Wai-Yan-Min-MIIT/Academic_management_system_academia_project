import pandas as pd

sheet1 = pd.read_excel('2015.xlsx', sheet_name='Sheet1')
grades = pd.read_excel('data.xlsx', sheet_name='GradePoint Data')
semester_grading = pd.read_excel('data_1.xlsx', sheet_name='SemesterGrading')

grade_map = {r.Grade: r['GradePointID'] for _, r in grades.iterrows()}

projects = sheet1[sheet1['CourseCode'].str.contains('PROJ')]

project_grading = projects[['ID', 'CourseCode', 'Grade']]

# Map grades
project_grading['GradePointID'] = project_grading['Grade'].map(grade_map)

# Map semester IDs to student IDs
sem_id_to_student = dict(zip(semester_grading['SemesterGradingID'],
                             semester_grading['StudentID']))

sheet1_ids = sheet1['ID']
semester_ids = semester_grading['SemesterGradingID']
id_to_sem = dict(zip(sheet1_ids, semester_ids))

project_grading['SemesterGradingID'] = project_grading['ID'].map(id_to_sem)
project_grading['StudentID'] = project_grading['SemesterGradingID'].map(sem_id_to_student)

project_grading = project_grading.rename(columns={'CourseCode':'ProjectCode'})
project_grading = project_grading[['StudentID', 'ProjectCode', 'GradePointID']]

with pd.ExcelWriter('data_1.xlsx', engine='openpyxl', mode='a') as writer:
    project_grading.to_excel(writer, sheet_name='ProjectGrading', index=False)

print("Project Grading Generated")